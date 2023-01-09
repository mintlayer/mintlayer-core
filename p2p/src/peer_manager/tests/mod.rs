// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod ban;
mod connections;

use std::{collections::BTreeSet, sync::Arc};

use common::primitives::semver::SemVer;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    event::PeerManagerEvent,
    net::{
        types::{Protocol, ProtocolType},
        ConnectivityService, NetworkingService,
    },
    peer_manager::PeerManager,
    P2pConfig,
};
async fn make_peer_manager_custom<T>(
    transport: T::Transport,
    addr: T::Address,
    chain_config: Arc<common::chain::ChainConfig>,
    p2p_config: Arc<P2pConfig>,
) -> (PeerManager<T>, UnboundedSender<PeerManagerEvent<T>>)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let (conn, _) = T::start(
        transport,
        vec![addr],
        Arc::clone(&chain_config),
        Default::default(),
    )
    .await
    .unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let (tx_sync, mut rx_sync) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move { while rx_sync.recv().await.is_some() {} });

    let peer_manager = PeerManager::<T>::new(chain_config, p2p_config, conn, rx, tx_sync).unwrap();

    (peer_manager, tx)
}

async fn make_peer_manager<T>(
    transport: T::Transport,
    addr: T::Address,
    chain_config: Arc<common::chain::ChainConfig>,
) -> PeerManager<T>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let p2p_config = Arc::new(P2pConfig::default());
    let (peer_manager, _tx) =
        make_peer_manager_custom::<T>(transport, addr, chain_config, p2p_config).await;
    peer_manager
}

async fn run_peer_manager<T>(
    transport: T::Transport,
    addr: T::Address,
    chain_config: Arc<common::chain::ChainConfig>,
    p2p_config: Arc<P2pConfig>,
) -> UnboundedSender<PeerManagerEvent<T>>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let (mut peer_manager, tx) =
        make_peer_manager_custom::<T>(transport, addr, chain_config, p2p_config).await;
    tokio::spawn(async move {
        peer_manager.run().await.unwrap();
    });
    tx
}

/// Returns a set of minimal required protocols.
pub fn default_protocols() -> BTreeSet<Protocol> {
    [
        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
        Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
        Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
    ]
    .into_iter()
    .collect()
}

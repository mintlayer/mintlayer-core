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
mod peerdb;

use std::{fmt::Debug, str::FromStr, sync::Arc};

use crate::{
    net::{ConnectivityService, NetworkingService},
    peer_manager::PeerManager,
    P2pConfig,
};

async fn make_peer_manager<T>(
    transport: T::Transport,
    addr: T::Address,
    chain_config: Arc<common::chain::ChainConfig>,
) -> PeerManager<T>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as NetworkingService>::Address: FromStr,
    <<T as NetworkingService>::Address as FromStr>::Err: Debug,
{
    let (conn, _) = T::start(
        transport,
        addr,
        Arc::clone(&chain_config),
        Default::default(),
    )
    .await
    .unwrap();
    let (_, rx) = tokio::sync::mpsc::unbounded_channel();
    let (tx_sync, mut rx_sync) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move { while rx_sync.recv().await.is_some() {} });

    let p2p_config = Arc::new(P2pConfig::default());
    PeerManager::<T>::new(chain_config, p2p_config, conn, rx, tx_sync)
}

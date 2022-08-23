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

use std::{collections::BTreeSet, fmt::Debug, str::FromStr, sync::Arc, time::Duration};

use tokio::time::timeout;

use common::primitives::semver::SemVer;

use crate::{
    net::{
        types::{ConnectivityEvent, PeerInfo, Protocol, ProtocolType},
        ConnectivityService, NetworkingService,
    },
    peer_manager::PeerManager,
    P2pConfig,
};

async fn make_peer_manager<T>(
    addr: T::Address,
    config: Arc<common::chain::ChainConfig>,
) -> PeerManager<T>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as NetworkingService>::Address: FromStr,
    <<T as NetworkingService>::Address as FromStr>::Err: Debug,
{
    let (conn, _, _) = T::start(addr, Arc::clone(&config), Default::default()).await.unwrap();
    let (_, rx) = tokio::sync::mpsc::unbounded_channel();
    let (tx_sync, mut rx_sync) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        loop {
            let _ = rx_sync.recv().await;
        }
    });

    let p2p_config = Arc::new(P2pConfig::new());
    PeerManager::<T>::new(Arc::clone(&config), p2p_config, conn, rx, tx_sync)
}

async fn connect_services<T>(
    conn1: &mut T::ConnectivityHandle,
    conn2: &mut T::ConnectivityHandle,
) -> (T::Address, PeerInfo<T>)
where
    T: NetworkingService + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr = timeout(Duration::from_secs(5), conn2.local_addr())
        .await
        .expect("local address fetch not to timeout")
        .unwrap()
        .unwrap();
    conn1.connect(addr).await.expect("dial to succeed");

    let (address, peer_info) = match timeout(Duration::from_secs(5), conn2.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::InboundAccepted { address, peer_info } => (address, peer_info),
            event => panic!("expected `InboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `InboundAccepted` in time"),
    };

    match timeout(Duration::from_secs(5), conn1.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::OutboundAccepted { .. } => {}
            event => panic!("expected `OutboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `OutboundAccepted` in time"),
    }

    (address, peer_info)
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

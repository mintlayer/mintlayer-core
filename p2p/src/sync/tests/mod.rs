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

use super::*;
use crate::{
    event::{PubSubControlEvent, SwarmEvent, SyncControlEvent},
    net::{libp2p::Libp2pService, types::ConnectivityEvent, ConnectivityService},
};
use chainstate::{make_chainstate, ChainstateConfig};
use libp2p::PeerId;
use std::time::Duration;
use tokio::time::timeout;

mod block_response;
mod connection;
mod header_response;
mod request_response;

async fn make_sync_manager<T>(
    addr: T::Address,
) -> (
    BlockSyncManager<T>,
    T::ConnectivityHandle,
    mpsc::UnboundedSender<SyncControlEvent<T>>,
    mpsc::UnboundedReceiver<PubSubControlEvent>,
    mpsc::UnboundedReceiver<SwarmEvent<T>>,
)
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
    let (tx_pubsub, rx_pubsub) = mpsc::unbounded_channel();
    let (tx_swarm, rx_swarm) = mpsc::unbounded_channel();
    let storage = chainstate_storage::inmemory::Store::new_empty().unwrap();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let chainstate_config = ChainstateConfig::new();
    let mut man = subsystem::Manager::new("TODO");
    let handle = man.add_subsystem(
        "consensus",
        make_chainstate(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap(),
    );
    tokio::spawn(async move { man.main().await });

    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (conn, _, sync) = T::start(addr, Arc::clone(&config), Default::default()).await.unwrap();

    (
        BlockSyncManager::<T>::new(
            Arc::clone(&config),
            sync,
            handle,
            rx_p2p_sync,
            tx_swarm,
            tx_pubsub,
        ),
        conn,
        tx_p2p_sync,
        rx_pubsub,
        rx_swarm,
    )
}

pub async fn connect_services<T>(
    conn1: &mut T::ConnectivityHandle,
    conn2: &mut T::ConnectivityHandle,
) where
    T: NetworkingService + std::fmt::Debug + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr = timeout(Duration::from_secs(5), conn2.local_addr())
        .await
        .expect("local address fetch not to timeout")
        .unwrap()
        .unwrap();
    conn1.connect(addr).await.expect("dial to succeed");

    match timeout(Duration::from_secs(5), conn2.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::InboundAccepted { .. } => {}
            event => panic!("expected `InboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `InboundAccepted` in time"),
    }

    match timeout(Duration::from_secs(5), conn1.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::OutboundAccepted { .. } => {}
            event => panic!("expected `OutboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `OutboundAccepted` in time"),
    }
}

async fn register_peer<T>(mgr: &mut BlockSyncManager<T>, peer_id: T::PeerId)
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let locator = mgr.chainstate_handle.call(|this| this.get_locator()).await.unwrap().unwrap();

    mgr.peers.insert(
        peer_id,
        peer::PeerContext::new_with_locator(peer_id, locator),
    );
}

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

use p2p::{
    error::{P2pError, PublishError},
    event::{PubSubControlEvent, SwarmEvent},
    message::Announcement,
    net::{
        self, libp2p::Libp2pService, mock::MockService, ConnectivityService, NetworkingService,
        PubSubService, SyncingMessagingService,
    },
    pubsub::PubSubMessageHandler,
    sync::BlockSyncManager,
};
use p2p_test_utils::{connect_services, make_libp2p_addr, make_mock_addr, TestBlockInfo};
use std::sync::Arc;
use tokio::sync::mpsc;

// start two libp2p services, spawn a `PubSubMessageHandler` for the first service,
// publish an invalid block from the first service and verify that the `PeerManager`
// of the first service receives a `AdjustPeerScore` event which bans the peer of
// the second service.
#[tokio::test]
async fn invalid_pubsub_block() {
    let (tx_pubsub, rx_pubsub) = mpsc::unbounded_channel();
    let (tx_swarm, mut rx_swarm) = mpsc::unbounded_channel();
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let handle = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;

    let (mut conn1, pubsub, _sync) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let mut pubsub1 = PubSubMessageHandler::<Libp2pService>::new(
        Arc::clone(&config),
        pubsub,
        handle.clone(),
        tx_swarm,
        rx_pubsub,
        &[net::types::PubSubTopic::Blocks],
    );

    let (mut conn2, mut pubsub2, _) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    // connect the services together, spawn `pubsub1` into the background
    // and subscriber to events
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    // create few blocks so `pubsub2` has something to send to `pubsub1`
    let best_block = TestBlockInfo::from_genesis(config.genesis_block());
    let blocks = p2p_test_utils::create_n_blocks(Arc::clone(&config), best_block, 3);

    tokio::spawn(async move {
        tx_pubsub.send(PubSubControlEvent::InitialBlockDownloadDone).unwrap();
        pubsub1.run().await
    });

    // spawn `pubsub2` into background and spam an orphan block on the network
    tokio::spawn(async move {
        pubsub2.subscribe(&[net::types::PubSubTopic::Blocks]).await.unwrap();

        loop {
            let res = pubsub2.publish(Announcement::Block(blocks[2].clone())).await;

            if res.is_ok() {
                break;
            } else {
                assert_eq!(
                    res,
                    Err(P2pError::PublishError(PublishError::InsufficientPeers))
                );
            }
        }
    });

    let event = rx_swarm.recv().await;
    if let Some(SwarmEvent::AdjustPeerScore(peer_id, score, _)) = event {
        assert_eq!(&peer_id, conn2.peer_id());
        assert_eq!(score, 100);
    } else {
        panic!("invalid event received: {:?}", event);
    }
}

// start two networking services and give an invalid block, verify that `PeerManager` is informed
async fn invalid_sync_block<T>(addr1: T::Address, addr2: T::Address)
where
    T: NetworkingService + std::fmt::Debug + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let (_tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
    let (tx_pubsub, _rx_pubsub) = mpsc::unbounded_channel();
    let (tx_swarm, mut rx_swarm) = mpsc::unbounded_channel();
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let handle = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;

    let (mut conn1, _, sync1) =
        T::start(addr1, Arc::clone(&config), Default::default()).await.unwrap();

    let (mut conn2, _, _sync2) =
        T::start(addr2, Arc::clone(&config), Default::default()).await.unwrap();

    let mut sync1 = BlockSyncManager::<T>::new(
        Arc::clone(&config),
        sync1,
        handle.clone(),
        rx_p2p_sync,
        tx_swarm,
        tx_pubsub,
    );

    connect_services::<T>(&mut conn1, &mut conn2).await;

    // create few blocks and offer an orphan block to the `SyncManager`
    let best_block = TestBlockInfo::from_genesis(config.genesis_block());
    let blocks = p2p_test_utils::create_n_blocks(Arc::clone(&config), best_block, 3);

    // register `conn2` to the `SyncManager`, process a block response
    // and verify the `PeerManager` is notified of the protocol violation
    let remote_id = *conn2.peer_id();

    tokio::spawn(async move {
        sync1.register_peer(remote_id).await.unwrap();
        let res = sync1.process_block_response(remote_id, vec![blocks[2].clone()]).await;
        sync1.handle_error(remote_id, res).await.unwrap();
    });

    if let Some(SwarmEvent::AdjustPeerScore(peer_id, score, _)) = rx_swarm.recv().await {
        assert_eq!(remote_id, peer_id);
        assert_eq!(score, 100);
    }
}

#[tokio::test]
async fn invalid_sync_block_libp2p() {
    invalid_sync_block::<Libp2pService>(make_libp2p_addr(), make_libp2p_addr()).await;
}

#[tokio::test]
async fn invalid_sync_block_mock() {
    invalid_sync_block::<MockService>(make_mock_addr(), make_mock_addr()).await;
}

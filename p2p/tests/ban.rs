// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(unused)]
use libp2p::Multiaddr;
use p2p::{
    error::{P2pError, PublishError},
    event::{PubSubControlEvent, SwarmEvent},
    message::Announcement,
    net::{
        self, libp2p::Libp2pService, types::ConnectivityEvent, ConnectivityService,
        NetworkingService, PubSubService,
    },
    pubsub::PubSubMessageHandler,
    sync::SyncManager,
};
use p2p_test_utils::{make_libp2p_addr, TestBlockInfo};
use std::sync::Arc;
use tokio::sync::mpsc;

async fn connect_services<T>(conn1: &mut T::ConnectivityHandle, conn2: &mut T::ConnectivityHandle)
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr = conn2.local_addr().await.unwrap().unwrap();
    let (_conn1_res, conn2_res) = tokio::join!(conn1.connect(addr), conn2.poll_next());
    let conn2_res: ConnectivityEvent<T> = conn2_res.unwrap();
    let _conn1_id = match conn2_res {
        ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
}

// start two libp2p services, spawn a `PubSubMessageHandler` for the first service,
// publish an invalid block from the first service and verify that the `PeerManager`
// of the first service receives a `AdjustPeerScore` event which bans the peer of
// the second service.
#[tokio::test]
async fn invalid_pubsub_block() {
    let (tx_pubsub, rx_pubsub) = mpsc::channel(16);
    let (tx_swarm, mut rx_swarm) = mpsc::channel(16);
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
        tx_pubsub.send(PubSubControlEvent::InitialBlockDownloadDone).await.unwrap();
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

// start two libp2p services and give an invalid block, verify that `PeerManager` is informed
#[tokio::test]
async fn invalid_sync_block() {
    let (tx_p2p_sync, rx_p2p_sync) = mpsc::channel(16);
    let (tx_pubsub, rx_pubsub) = mpsc::channel(16);
    let (tx_swarm, mut rx_swarm) = mpsc::channel(16);
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let handle = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;

    let (mut conn1, _, sync1) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let mut sync1 = SyncManager::<Libp2pService>::new(
        Arc::clone(&config),
        sync1,
        handle.clone(),
        rx_p2p_sync,
        tx_swarm,
        tx_pubsub,
    );

    // create few blocks and offer an orphan block to the `SyncManager`
    let best_block = TestBlockInfo::from_genesis(config.genesis_block());
    let blocks = p2p_test_utils::create_n_blocks(Arc::clone(&config), best_block, 3);

    // register random peer to the `SyncManager`, process a block response
    // and verify the `PeerManager` is notified of the protocol violation
    let remote_id = libp2p::PeerId::random();

    tokio::spawn(async move {
        sync1.register_peer(remote_id).await.unwrap();
        let res = sync1.process_block_response(remote_id, vec![blocks[2].clone()]).await;
        let res = sync1.handle_error(remote_id, res).await;
    });

    if let Some(SwarmEvent::AdjustPeerScore(peer_id, score, _)) = rx_swarm.recv().await {
        assert_eq!(remote_id, peer_id);
        assert_eq!(score, 100);
    }
}

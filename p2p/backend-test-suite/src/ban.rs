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

use std::{fmt::Debug, sync::Arc};

use tokio::sync::mpsc;

use p2p::{
    error::{P2pError, PublishError},
    event::SwarmEvent,
    message::{Announcement, HeaderListResponse, Request, Response},
    net::{
        self, types::SyncingEvent, ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    peer_manager::helpers::connect_services,
    sync::BlockSyncManager,
};
use p2p_test_utils::{MakeTestAddress, TestBlockInfo};

tests![invalid_pubsub_block, invalid_sync_block,];

// Start two network services, spawn a `SyncMessageHandler` for the first service, publish an
// invalid block from the first service and verify that the `SyncManager` of the first service
// receives a `AdjustPeerScore` event which bans the peer of the second service.
async fn invalid_pubsub_block<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let (_tx_sync, rx_sync) = mpsc::unbounded_channel();
    let (tx_swarm, mut rx_swarm) = mpsc::unbounded_channel();
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let handle = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;

    let (mut conn1, sync1) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();

    let mut sync1 = BlockSyncManager::<S>::new(
        Arc::clone(&config),
        sync1,
        handle.clone(),
        rx_sync,
        tx_swarm,
    );

    let (mut conn2, mut sync2) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    connect_services::<S>(&mut conn1, &mut conn2).await;

    // create few blocks so `sync2` has something to send to `sync1`
    let best_block = TestBlockInfo::from_genesis(config.genesis_block());
    let blocks = p2p_test_utils::create_n_blocks(Arc::clone(&config), best_block, 3);

    let peer = *conn2.peer_id();
    tokio::spawn(async move {
        sync1.register_peer(peer).await.unwrap();
        sync1.run().await
    });

    // spawn `sync2` into background and spam an orphan block on the network
    tokio::spawn(async move {
        sync2.subscribe(&[net::types::PubSubTopic::Blocks]).await.unwrap();

        let request_id = match sync2.poll_next().await.unwrap() {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(_),
            } => request_id,
            e => panic!("Unexpected event type: {e:?}"),
        };
        sync2
            .send_response(
                request_id,
                Response::HeaderListResponse(HeaderListResponse::new(Vec::new())),
            )
            .await
            .unwrap();

        loop {
            let res = sync2.make_announcement(Announcement::Block(blocks[2].clone())).await;

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

    match rx_swarm.recv().await {
        Some(SwarmEvent::AdjustPeerScore(peer_id, score, _)) => {
            assert_eq!(&peer_id, conn2.peer_id());
            assert_eq!(score, 100);
        }
        e => panic!("invalid event received: {e:?}"),
    }
}

// Start two networking services and give an invalid block, verify that `PeerManager` is informed.
async fn invalid_sync_block<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let (_tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
    let (tx_swarm, mut rx_swarm) = mpsc::unbounded_channel();
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let handle = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;

    let (mut conn1, sync1) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();

    let (mut conn2, _sync2) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();

    let mut sync1 = BlockSyncManager::<S>::new(
        Arc::clone(&config),
        sync1,
        handle.clone(),
        rx_p2p_sync,
        tx_swarm,
    );

    connect_services::<S>(&mut conn1, &mut conn2).await;

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

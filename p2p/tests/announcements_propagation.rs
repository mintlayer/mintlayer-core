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

use tokio::sync::mpsc::unbounded_channel;

use p2p::{
    message::{AnnouncementType, HeaderListResponse, Request, Response},
    net::{
        libp2p::Libp2pService,
        mock::{
            transport::{ChannelMockTransport, TcpMockTransport},
            MockService,
        },
        types::{PubSubTopic, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    sync::BlockSyncManager,
};
use p2p_test_utils::{
    connect_services, MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress,
    TestBlockInfo,
};

async fn announcements_propagation<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let chainstate_handle = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;

    let (mut conn1, sync1) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();
    let (mut conn2, sync2) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();
    let (mut conn3, mut sync3) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    // Create first sync manager.
    let (_tx_sync, rx_sync) = unbounded_channel();
    let (tx_swarm, _rx_swarm) = unbounded_channel();
    let mut sync1 = BlockSyncManager::<S>::new(
        Arc::clone(&config),
        sync1,
        chainstate_handle.clone(),
        rx_sync,
        tx_swarm,
    );

    // Create second sync manager.
    let (_tx_sync, rx_sync) = unbounded_channel();
    let (tx_swarm, _rx_swarm) = unbounded_channel();
    let mut sync2 = BlockSyncManager::<S>::new(
        Arc::clone(&config),
        sync2,
        p2p_test_utils::start_chainstate(Arc::clone(&config)).await,
        rx_sync,
        tx_swarm,
    );

    connect_services::<S>(&mut conn1, &mut conn2).await;
    connect_services::<S>(&mut conn1, &mut conn3).await;
    connect_services::<S>(&mut conn2, &mut conn3).await;

    sync1.register_peer(*conn2.peer_id()).await.unwrap();
    sync1.register_peer(*conn3.peer_id()).await.unwrap();

    sync2.register_peer(*conn1.peer_id()).await.unwrap();
    sync2.register_peer(*conn3.peer_id()).await.unwrap();

    sync3.subscribe(&[PubSubTopic::Blocks]).await.unwrap();

    // Start sync managers.
    tokio::spawn(async move { sync1.run().await });
    tokio::spawn(async move { sync2.run().await });

    // Respond with HeaderListResponse to both managers.
    let request_id = match sync3.poll_next().await.unwrap() {
        SyncingEvent::Request {
            peer_id: _,
            request_id,
            request: Request::HeaderListRequest(_),
        } => request_id,
        e => panic!("Unexpected event type: {e:?}"),
    };
    sync3
        .send_response(
            request_id,
            Response::HeaderListResponse(HeaderListResponse::new(Vec::new())),
        )
        .await
        .unwrap();
    let request_id = match sync3.poll_next().await.unwrap() {
        SyncingEvent::Request {
            peer_id: _,
            request_id,
            request: Request::HeaderListRequest(_),
        } => request_id,
        e => panic!("Unexpected event type: {e:?}"),
    };
    sync3
        .send_response(
            request_id,
            Response::HeaderListResponse(HeaderListResponse::new(Vec::new())),
        )
        .await
        .unwrap();

    // TODO: FIXME:
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Add a block.
    let block = p2p_test_utils::create_block(
        Arc::clone(&config),
        TestBlockInfo::from_tip(&chainstate_handle, &config).await,
    );
    p2p_test_utils::import_blocks(&chainstate_handle, vec![block.clone()]).await;

    // Check the original announcement.
    match sync3.poll_next().await.unwrap() {
        SyncingEvent::Announcement {
            peer_id,
            message_id: _,
            announcement,
        } => {
            assert!(!announcement.is_propagated());
            assert_eq!(&peer_id, conn1.peer_id());

            match announcement.announcement() {
                AnnouncementType::Block(b) => assert_eq!(b, &block),
            }
        }
        e => panic!("Unexpected event: {e:?}"),
    }

    // And the propagated one.
    match sync3.poll_next().await.unwrap() {
        SyncingEvent::Announcement {
            peer_id,
            message_id: _,
            announcement,
        } => {
            assert!(announcement.is_propagated());
            assert_eq!(&peer_id, conn2.peer_id());

            match announcement.announcement() {
                AnnouncementType::Block(b) => assert_eq!(b, &block),
            }
        }
        e => panic!("Unexpected event: {e:?}"),
    }
}

#[tokio::test]
async fn announcements_propagation_libp2p() {
    announcements_propagation::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn announcements_propagation_mock_tcp() {
    announcements_propagation::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn announcements_propagation_mock_channels() {
    announcements_propagation::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

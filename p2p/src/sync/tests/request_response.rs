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

use std::{collections::HashSet, fmt::Debug, time::Duration};

use tokio::time::timeout;

use chainstate::Locator;

use crate::{
    message::{HeaderListRequest, HeaderListResponse, Request, Response},
    net::{
        libp2p::Libp2pService,
        mock::{
            transport::{ChannelMockTransport, TcpMockTransport},
            MockService,
        },
        types::SyncingEvent,
    },
    peer_manager::helpers::connect_services,
    sync::tests::make_sync_manager,
    ConnectivityService, NetworkingService, SyncingMessagingService,
};
use p2p_test_utils::{MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress};

async fn request_response<A, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    T: NetworkingService + Debug + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr1, mut conn1, _sync1, _pm1) = make_sync_manager::<T>(A::make_address()).await;
    let (mut mgr2, mut conn2, _sync2, _pm2) = make_sync_manager::<T>(A::make_address()).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<T>(&mut conn1, &mut conn2).await;

    mgr1.peer_sync_handle
        .send_request(
            *conn2.peer_id(),
            Request::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![]))),
        )
        .await
        .unwrap();

    if let Ok(SyncingEvent::Request {
        peer_id: _,
        request_id,
        request,
    }) = mgr2.peer_sync_handle.poll_next().await
    {
        assert_eq!(
            request,
            Request::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![])))
        );

        mgr2.peer_sync_handle
            .send_response(
                request_id,
                Response::HeaderListResponse(HeaderListResponse::new(vec![])),
            )
            .await
            .unwrap();
    } else {
        panic!("invalid data received");
    }
}

#[tokio::test]
async fn request_response_libp2p() {
    request_response::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn request_response_mock_tcp() {
    request_response::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn request_response_mock_channels() {
    request_response::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

async fn multiple_requests_and_responses<A, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    T: NetworkingService + 'static + Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let (mut mgr1, mut conn1, _sync1, _pm1) = make_sync_manager::<T>(addr1).await;
    let (mut mgr2, mut conn2, _sync2, _pm2) = make_sync_manager::<T>(addr2).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<T>(&mut conn1, &mut conn2).await;
    let mut request_ids = HashSet::new();

    let id = mgr1
        .peer_sync_handle
        .send_request(
            *conn2.peer_id(),
            Request::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![]))),
        )
        .await
        .unwrap();
    request_ids.insert(id);

    let id = mgr1
        .peer_sync_handle
        .send_request(
            *conn2.peer_id(),
            Request::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![]))),
        )
        .await
        .unwrap();
    request_ids.insert(id);

    assert_eq!(request_ids.len(), 2);

    for i in 0..2 {
        match timeout(Duration::from_secs(15), mgr2.peer_sync_handle.poll_next()).await {
            Ok(event) => match event {
                Ok(SyncingEvent::Request { request_id, .. }) => {
                    mgr2.peer_sync_handle
                        .send_response(
                            request_id,
                            Response::HeaderListResponse(HeaderListResponse::new(vec![])),
                        )
                        .await
                        .unwrap();
                }
                _ => panic!("invalid event: {:?}", event),
            },
            Err(_) => panic!("did not receive `Request` in time, iter {}", i),
        }
    }

    for i in 0..2 {
        match timeout(Duration::from_secs(15), mgr1.peer_sync_handle.poll_next()).await {
            Ok(event) => match event {
                Ok(SyncingEvent::Response { request_id, .. }) => {
                    request_ids.remove(&request_id);
                }
                _ => panic!("invalid event: {:?}", event),
            },
            Err(_) => panic!("did not receive `Response` in time, iter {}", i),
        }
    }

    assert!(request_ids.is_empty());
}

#[tokio::test]
async fn multiple_requests_and_responses_libp2p() {
    multiple_requests_and_responses::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn multiple_requests_and_responses_mock_tcp() {
    multiple_requests_and_responses::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn multiple_requests_and_responses_mock_channels() {
    multiple_requests_and_responses::<MakeChannelAddress, MockService<ChannelMockTransport>>()
        .await;
}

// Receive getheaders before receiving the `Connected` event from the peer manager which makes the
// request be rejected and time out in the sender's end.
async fn request_timeout<A, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr1, mut conn1, _sync1, _pm1) = make_sync_manager::<T>(A::make_address()).await;
    let (mut mgr2, mut conn2, _sync2, _pm2) = make_sync_manager::<T>(A::make_address()).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<T>(&mut conn1, &mut conn2).await;
    let peer2_id = *conn2.peer_id();

    tokio::spawn(async move {
        mgr1.register_peer(peer2_id).await.unwrap();

        match mgr1.peer_sync_handle.poll_next().await.unwrap() {
            SyncingEvent::RequestTimeout {
                peer_id,
                request_id: _,
            } => {
                assert_eq!(peer_id, peer2_id);
                mgr1.unregister_peer(peer_id);
            }
            _ => panic!("invalid event received"),
        }
    });

    match timeout(Duration::from_secs(5), mgr2.peer_sync_handle.poll_next()).await {
        Ok(event) => match event {
            Ok(SyncingEvent::Request { .. }) => {}
            _ => panic!("invalid event: {:?}", event),
        },
        Err(_) => panic!("did not receive `Request` in time"),
    }

    match timeout(Duration::from_secs(5), mgr2.peer_sync_handle.poll_next()).await {
        Ok(event) => match event {
            Ok(SyncingEvent::RequestTimeout { .. }) => {}
            _ => panic!("invalid event: {:?}", event),
        },
        Err(_) => panic!("did not receive `Error` in time"),
    }
}

#[tokio::test]
async fn request_timeout_libp2p() {
    request_timeout::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn request_timeout_mock_tcp() {
    request_timeout::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn request_timeout_mock_channels() {
    request_timeout::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

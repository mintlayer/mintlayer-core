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
use crate::{message::*, net::mock::MockService};
use p2p_test_utils::{make_libp2p_addr, make_mock_addr};
use std::{collections::HashSet, time::Duration};
use tokio::time::timeout;

async fn test_request_response<T>(addr1: T::Address, addr2: T::Address)
where
    T: NetworkingService + std::fmt::Debug + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr1, mut conn1, _sync1, _pubsub1, _swarm1) = make_sync_manager::<T>(addr1).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) = make_sync_manager::<T>(addr2).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<T>(&mut conn1, &mut conn2).await;

    mgr1.peer_sync_handle
        .send_request(
            *conn2.peer_id(),
            Request::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![]))),
        )
        .await
        .unwrap();

    if let Ok(net::types::SyncingEvent::Request {
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
async fn test_request_response_libp2p() {
    test_request_response::<Libp2pService>(make_libp2p_addr(), make_libp2p_addr()).await;
}

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn test_request_response_mock() {
    test_request_response::<MockService>(make_mock_addr(), make_mock_addr()).await;
}

async fn test_multiple_requests_and_responses<T>(addr1: T::Address, addr2: T::Address)
where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr1, mut conn1, _sync1, _pubsub1, _swarm1) = make_sync_manager::<T>(addr1).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) = make_sync_manager::<T>(addr2).await;

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
                Ok(net::types::SyncingEvent::Request { request_id, .. }) => {
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
                Ok(net::types::SyncingEvent::Response { request_id, .. }) => {
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
async fn test_multiple_requests_and_responses_libp2p() {
    test_multiple_requests_and_responses::<Libp2pService>(make_libp2p_addr(), make_libp2p_addr())
        .await;
}

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn test_multiple_requests_and_responses_mock() {
    test_multiple_requests_and_responses::<MockService>(make_mock_addr(), make_mock_addr()).await;
}

// receive getheaders before receiving `Connected` event from swarm manager
// which makes the request to be rejected and to time out in the sender end
async fn test_request_timeout_error<T>(addr1: T::Address, addr2: T::Address)
where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr1, mut conn1, _sync1, _pubsub1, _swarm1) = make_sync_manager::<T>(addr1).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) = make_sync_manager::<T>(addr2).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<T>(&mut conn1, &mut conn2).await;
    let peer2_id = *conn2.peer_id();

    tokio::spawn(async move {
        mgr1.register_peer(peer2_id).await.unwrap();

        match mgr1.peer_sync_handle.poll_next().await.unwrap() {
            net::types::SyncingEvent::Error {
                peer_id,
                request_id,
                error,
            } => {
                assert_eq!(error, net::types::RequestResponseError::Timeout);
                mgr1.process_error(peer_id, request_id, error).await.unwrap();
            }
            _ => panic!("invalid event received"),
        }
    });

    match timeout(Duration::from_secs(15), mgr2.peer_sync_handle.poll_next()).await {
        Ok(event) => match event {
            Ok(net::types::SyncingEvent::Request { .. }) => {}
            _ => panic!("invalid event: {:?}", event),
        },
        Err(_) => panic!("did not receive `Request` in time"),
    }

    match timeout(Duration::from_secs(15), mgr2.peer_sync_handle.poll_next()).await {
        Ok(event) => match event {
            Ok(net::types::SyncingEvent::Error { .. }) => {}
            _ => panic!("invalid event: {:?}", event),
        },
        Err(_) => panic!("did not receive `Error` in time"),
    }

    match timeout(Duration::from_secs(15), mgr2.peer_sync_handle.poll_next()).await {
        Ok(event) => match event {
            Ok(net::types::SyncingEvent::Request { .. }) => {}
            _ => panic!("invalid event: {:?}", event),
        },
        Err(_) => panic!("did not receive `Request` in time"),
    }
}

#[tokio::test]
async fn test_request_timeout_error_libp2p() {
    test_request_timeout_error::<Libp2pService>(make_libp2p_addr(), make_libp2p_addr()).await;
}

#[tokio::test]
#[ignore]
async fn test_request_timeout_error_mock() {
    test_request_timeout_error::<MockService>(make_mock_addr(), make_mock_addr()).await;
}

// verify that if after three retries the remote peer still
// hasn't responded to our request, the connection is closed
//
// marked as ignored as it takes quite a long time to complete
async fn request_timeout<T>(addr1: T::Address, addr2: T::Address)
where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr1, mut conn1, _sync1, _pubsub1, mut swarm_rx) = make_sync_manager::<T>(addr1).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) = make_sync_manager::<T>(addr2).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<T>(&mut conn1, &mut conn2).await;
    let _peer2_id = *conn2.peer_id();

    tokio::spawn(async move {
        mgr1.register_peer(_peer2_id).await.unwrap();

        for _ in 0..4 {
            match mgr1.peer_sync_handle.poll_next().await.unwrap() {
                net::types::SyncingEvent::Error {
                    peer_id,
                    request_id,
                    error,
                } => {
                    assert_eq!(error, net::types::RequestResponseError::Timeout);
                    mgr1.process_error(peer_id, request_id, error).await.unwrap();
                }
                _ => panic!("invalid event received"),
            }
        }

        let (_tx, rx) = oneshot::channel();
        assert!(std::matches!(
            swarm_rx.try_recv(),
            Ok(SwarmEvent::Disconnect(_peer2_id, _tx))
        ));
        assert_eq!(rx.await, Ok(()));
    });

    for _ in 0..8 {
        assert!(std::matches!(
            mgr2.peer_sync_handle.poll_next().await,
            Ok(net::types::SyncingEvent::Request { .. } | net::types::SyncingEvent::Error { .. })
        ));
    }
}

#[tokio::test]
#[ignore]
async fn request_timeout_libp2p() {
    request_timeout::<Libp2pService>(make_libp2p_addr(), make_libp2p_addr()).await;
}

#[tokio::test]
#[ignore]
async fn request_timeout_mock() {
    request_timeout::<MockService>(make_mock_addr(), make_mock_addr()).await;
}

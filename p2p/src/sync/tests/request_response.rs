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

use std::{fmt::Debug, time::Duration};

use tokio::time::timeout;

use chainstate::Locator;

use crate::{
    message::{HeaderListRequest, HeaderListResponse, SyncMessage},
    net::{
        default_backend::{
            transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            DefaultNetworkingService,
        },
        types::SyncingEvent,
    },
    sync::tests::make_sync_manager,
    testing_utils::{
        connect_services, TestTransportChannel, TestTransportMaker, TestTransportNoise,
        TestTransportTcp,
    },
    ConnectivityService, NetworkingService, SyncingMessagingService,
};

async fn request_response<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + Debug + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr1, mut conn1, _sync1, _pm1) =
        make_sync_manager::<T>(A::make_transport(), A::make_address()).await;
    let (mut mgr2, mut conn2, _sync2, _pm2) =
        make_sync_manager::<T>(A::make_transport(), A::make_address()).await;

    // connect the two managers together so that they can exchange messages
    let (_address, _peer_info1, peer_info2) = connect_services::<T>(&mut conn1, &mut conn2).await;

    mgr1.messaging_handle
        .send_message(
            peer_info2.peer_id,
            SyncMessage::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![]))),
        )
        .unwrap();

    if let Ok(SyncingEvent::Message { peer, message }) = mgr2.messaging_handle.poll_next().await {
        assert_eq!(
            message,
            SyncMessage::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![])))
        );

        mgr2.messaging_handle
            .send_message(
                peer,
                SyncMessage::HeaderListResponse(HeaderListResponse::new(vec![])),
            )
            .unwrap();
    } else {
        panic!("invalid data received");
    }
}

#[tokio::test]
async fn request_response_tcp() {
    request_response::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn request_response_channels() {
    request_response::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>()
        .await;
}

#[tokio::test]
async fn test_request_response_noise() {
    request_response::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn multiple_requests_and_responses<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let (mut mgr1, mut conn1, _sync1, _pm1) =
        make_sync_manager::<T>(A::make_transport(), addr1).await;
    let (mut mgr2, mut conn2, _sync2, _pm2) =
        make_sync_manager::<T>(A::make_transport(), addr2).await;

    // connect the two managers together so that they can exchange messages
    let (_address, _peer_info1, peer_info2) = connect_services::<T>(&mut conn1, &mut conn2).await;
    let mut requests = 0;

    mgr1.messaging_handle
        .send_message(
            peer_info2.peer_id,
            SyncMessage::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![]))),
        )
        .unwrap();
    requests += 1;

    mgr1.messaging_handle
        .send_message(
            peer_info2.peer_id,
            SyncMessage::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![]))),
        )
        .unwrap();
    requests += 1;

    assert_eq!(requests, 2);

    for i in 0..2 {
        match timeout(Duration::from_secs(15), mgr2.messaging_handle.poll_next()).await {
            Ok(event) => match event {
                Ok(SyncingEvent::Message { peer, .. }) => {
                    mgr2.messaging_handle
                        .send_message(
                            peer,
                            SyncMessage::HeaderListResponse(HeaderListResponse::new(vec![])),
                        )
                        .unwrap();
                }
                _ => panic!("invalid event: {event:?}"),
            },
            Err(_) => panic!("did not receive `Request` in time, iter {i}"),
        }
    }

    for i in 0..2 {
        match timeout(Duration::from_secs(15), mgr1.messaging_handle.poll_next()).await {
            Ok(event) => match event {
                Ok(SyncingEvent::Message { .. }) => {
                    requests -= 1;
                }
                _ => panic!("invalid event: {event:?}"),
            },
            Err(_) => panic!("did not receive `Response` in time, iter {i}"),
        }
    }

    assert_eq!(0, requests);
}

#[tokio::test]
async fn multiple_requests_and_responses_tcp() {
    multiple_requests_and_responses::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn multiple_requests_and_responses_channels() {
    multiple_requests_and_responses::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn multiple_requests_and_responses_noise() {
    multiple_requests_and_responses::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

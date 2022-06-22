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
use super::*;

#[tokio::test]
async fn test_request_response() {
    let (mut mgr1, mut conn1, _sync1, _pubsub1, _swarm1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    mgr1.handle
        .send_request(
            *conn2.peer_id(),
            Message {
                magic: [5, 6, 7, 8],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: vec![],
                })),
            },
        )
        .await
        .unwrap();

    if let Ok(net::types::SyncingEvent::Request {
        peer_id: _,
        request_id,
        request,
    }) = mgr2.handle.poll_next().await
    {
        assert_eq!(
            request,
            Message {
                magic: [5, 6, 7, 8],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: vec![]
                }))
            }
        );

        mgr2.handle
            .send_response(
                request_id,
                Message {
                    magic: [5, 6, 7, 8],
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers: vec![],
                    })),
                },
            )
            .await
            .unwrap();
    } else {
        panic!("invalid data received");
    }
}

#[tokio::test]
async fn test_multiple_requests_and_responses() {
    let (mut mgr1, mut conn1, _sync1, _pubsub1, _swarm1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    mgr1.handle
        .send_request(
            *conn2.peer_id(),
            Message {
                magic: [1, 2, 3, 4],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: vec![],
                })),
            },
        )
        .await
        .unwrap();

    mgr1.handle
        .send_request(
            *conn2.peer_id(),
            Message {
                magic: [5, 6, 7, 8],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: vec![],
                })),
            },
        )
        .await
        .unwrap();

    for _ in 0..2 {
        if let Ok(net::types::SyncingEvent::Request {
            peer_id: _,
            request_id,
            request,
        }) = mgr2.handle.poll_next().await
        {
            if let Message {
                magic,
                msg:
                    MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                        locator: _,
                    })),
            } = request
            {
                mgr2.handle
                    .send_response(
                        request_id,
                        Message {
                            magic,
                            msg: MessageType::Syncing(SyncingMessage::Response(
                                SyncingResponse::Headers { headers: vec![] },
                            )),
                        },
                    )
                    .await
                    .unwrap();
            }
        } else {
            panic!("invalid data received");
        }
    }

    let mut magic_seen = 0;
    for _ in 0..2 {
        if let Ok(net::types::SyncingEvent::Response {
            peer_id: _,
            request_id: _,
            response,
        }) = mgr1.handle.poll_next().await
        {
            if let Message {
                magic,
                msg:
                    MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers: _,
                    })),
            } = response
            {
                if magic == [1, 2, 3, 4] {
                    magic_seen += 1;
                } else {
                    assert_eq!(magic, [5, 6, 7, 8]);
                    magic_seen += 1;
                }
            }
        } else {
            panic!("invalid data received");
        }
    }

    assert_eq!(magic_seen, 2);
}

// receive getheaders before receiving `Connected` event from swarm manager
// which makes the request to be rejected and to time out in the sender end
#[tokio::test]
async fn test_request_timeout_error() {
    let (mut mgr1, mut conn1, _sync1, _pubsub1, _swarm1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;
    let peer2_id = *conn2.peer_id();

    tokio::spawn(async move {
        mgr1.register_peer(peer2_id).await.unwrap();

        match mgr1.handle.poll_next().await.unwrap() {
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

    for _ in 0..3 {
        assert!(std::matches!(
            mgr2.handle.poll_next().await,
            Ok(net::types::SyncingEvent::Request { .. } | net::types::SyncingEvent::Error { .. })
        ));
    }
}

// verify that if after three retries the remote peer still
// hasn't responded to our request, the connection is closed
//
// marked as ignored as it takes quite a long time to complete
#[ignore]
#[tokio::test]
async fn request_timeout() {
    let (mut mgr1, mut conn1, _sync1, _pubsub1, mut swarm_rx) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _sync2, _pubsub2, _swarm2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;
    let _peer2_id = *conn2.peer_id();

    tokio::spawn(async move {
        mgr1.register_peer(_peer2_id).await.unwrap();

        for _ in 0..4 {
            match mgr1.handle.poll_next().await.unwrap() {
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

    for _ in 0..4 {
        assert!(std::matches!(
            mgr2.handle.poll_next().await,
            Ok(net::types::SyncingEvent::Request { .. })
        ));
        assert!(std::matches!(
            mgr2.handle.poll_next().await,
            Ok(net::types::SyncingEvent::Error { .. })
        ));
    }
}

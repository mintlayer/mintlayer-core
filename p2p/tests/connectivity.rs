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

use common::{
    chain::{config, ChainConfig},
    primitives::time,
};
use p2p::{
    error::{P2pError, ProtocolError},
    message::*,
    net::{mock::MockService, SocketService},
    peer::*,
    proto::connectivity::*,
    proto::handshake::{HandshakeState, OutboundHandshakeState},
};
use std::sync::Arc;

async fn create_two_peers(config: Arc<ChainConfig>) -> (Peer<MockService>, Peer<MockService>) {
    let (mut local, mut remote) = test_utils::create_two_mock_peers(Arc::clone(&config)).await;

    // handshake with remove
    local
        .on_handshake_event(
            HandshakeState::Outbound(OutboundHandshakeState::Initiate),
            HandshakeMessage::Hello {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            },
        )
        .await
        .unwrap();

    // respond to Hello with HelloAck
    let msg = remote.socket.recv().await;
    remote.on_peer_event(msg).await.unwrap();

    // read HelloAck and conclude handshake
    let msg = local.socket.recv().await;
    local.on_peer_event(msg).await.unwrap();

    (local, remote)
}

// helper function to retransmit Ping and verify peer state
async fn ping_retry(peer: &mut Peer<MockService>, retries: isize) {
    // resend the ping `retries` times and verify on each iteration that local peer's state updates correctly
    for retry in 0..retries {
        // verify peer state
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = peer.state
        {
            assert_eq!(retries, retry);
        } else {
            unreachable!();
        }

        // manually trigger `PingRetry` event
        peer.on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: PING_MAX_RETRIES,
        }))
        .await
        .unwrap();
    }
}

// send ping, respond with pong
#[tokio::test]
async fn test_valid_ping_pong() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // verify local state
    if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
        nonce: _,
        retries,
    })) = local.state
    {
        assert_eq!(retries, 0isize);
    } else {
        unreachable!();
    }

    // read Ping and verify state of remote peer
    let msg = remote.socket.recv().await;
    remote.on_peer_event(msg).await.unwrap();
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // read Pong and verify state of local peer
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));
    assert_eq!(
        local.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    // trigger PingRetry event manually and verify final state
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: 3isize,
        }))
        .await
        .unwrap();
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

// do not respond to ping at all
#[tokio::test]
async fn test_no_response() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // transmit Ping 3 times
    ping_retry(&mut local, PING_MAX_RETRIES).await;

    // verify that local peer considers remote unresponsive (as it should)
    assert_eq!(
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await,
        Err(P2pError::ProtocolError(ProtocolError::Unresponsive))
    );
}

// respond to ping on the first retry
#[tokio::test]
async fn test_late_response_on_1st_retry() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // transmit Ping onces
    ping_retry(&mut local, 1).await;

    // read Ping and verify state of remote peer
    let msg = remote.socket.recv().await;
    remote.on_peer_event(msg).await.unwrap();
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // read Pong and verify state of local peer
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));
    assert_eq!(
        local.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    // trigger PingRetry event manually and verify final state
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: 3isize,
        }))
        .await
        .unwrap();
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

// respond to ping on the second retry
#[tokio::test]
async fn test_late_response_on_2nd_retry() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // transmit Ping onces
    ping_retry(&mut local, 2).await;

    // read Ping and verify state of remote peer
    let msg = remote.socket.recv().await;
    remote.on_peer_event(msg).await.unwrap();
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // read Pong and verify state of local peer
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));
    assert_eq!(
        local.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    // trigger PingRetry event manually and verify final state
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: 3isize,
        }))
        .await
        .unwrap();
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

// respond to ping on the third and last retry
#[tokio::test]
async fn test_late_response_on_3rd_retry() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // transmit Ping onces
    ping_retry(&mut local, PING_MAX_RETRIES).await;

    // read Ping and verify state of remote peer
    let msg = remote.socket.recv().await;
    remote.on_peer_event(msg).await.unwrap();
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // read Pong and verify state of local peer
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));
    assert_eq!(
        local.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    // trigger PingRetry event manually and verify final state
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: 3isize,
        }))
        .await
        .unwrap();
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

// respond to ping but with invalid nonce
#[tokio::test]
async fn test_send_pong_invalid_nonce() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // verify local state
    let nonce =
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

    // resend the ping N times and respond to it each time with an invalid Pong
    for retry in 0..PING_MAX_RETRIES {
        // send Pong with invalid nonce
        remote
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Connectivity(ConnectivityMessage::Pong {
                    nonce: nonce.wrapping_add(1),
                }),
            })
            .await
            .unwrap();

        // read Pong from socket and verify that state remains as `PingRetry`
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));

        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = local.state
        {
            assert_eq!(retries, retry);
        } else {
            unreachable!();
        }

        // manually trigger `PingRetry` event
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();
    }

    // verify that local peer considers remote unresponsive (as it should)
    assert_eq!(
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await,
        Err(P2pError::ProtocolError(ProtocolError::Unresponsive))
    );
}

// respond to ping first with invalid nonce and then with valid nonce
#[tokio::test]
async fn test_send_pong_invalid_then_valid_nonce() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // verify local state
    let nonce =
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

    // send Pong with invalid nonce
    remote
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Connectivity(ConnectivityMessage::Pong {
                nonce: nonce.wrapping_add(1),
            }),
        })
        .await
        .unwrap();

    // read Pong from socket and verify that state remains as `PingRetry`
    // meaning that the Pong was rejected
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));

    if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
        nonce: _,
        retries,
    })) = local.state
    {
        assert_eq!(retries, 0isize);
    } else {
        unreachable!();
    }

    // manually trigger `PingRetry` event
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: PING_MAX_RETRIES,
        }))
        .await
        .unwrap();

    if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
        nonce: _,
        retries,
    })) = local.state
    {
        assert_eq!(retries, 1isize);
    } else {
        unreachable!();
    }

    // send Pong with valid nonce
    remote
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce }),
        })
        .await
        .unwrap();

    // read Pong from socket and verify that state has changed to `PongReceived`
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));
    assert_eq!(
        local.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    // manually trigger `PingRetry` event and verify that has changed to `ListeningState::Any`
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: PING_MAX_RETRIES,
        }))
        .await
        .unwrap();
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

// respond to ping first with invalid nonce, then miss first and second retry
// and then finally respond to the last retry with correct nonce
#[tokio::test]
async fn test_send_pong_invalid_nonce_late_response() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // verify local state
    let nonce =
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

    // send Pong with invalid nonce
    remote
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Connectivity(ConnectivityMessage::Pong {
                nonce: nonce.wrapping_add(1),
            }),
        })
        .await
        .unwrap();

    // read Pong from socket and verify that state remains as `PingRetry`
    // meaning that the Pong was rejected
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));

    if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
        nonce: _,
        retries,
    })) = local.state
    {
        assert_eq!(retries, 0isize);
    } else {
        unreachable!();
    }

    // transmit Ping onces
    ping_retry(&mut local, PING_MAX_RETRIES).await;

    // send Pong with valid nonce
    remote
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce }),
        })
        .await
        .unwrap();

    // read Pong from socket and verify that state has changed to `PongReceived`
    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));
    assert_eq!(
        local.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    // manually trigger `PingRetry` event and verify that has changed to `ListeningState::Any`
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: PING_MAX_RETRIES,
        }))
        .await
        .unwrap();
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

// Simultaneously send ping messages and verify that both peers
// conclude the connectivity check correctly by sending a pong with
// correct nonce and expecing a pong with correct nonce back
#[tokio::test]
async fn test_simultaneous_ping() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // verify local state
    if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
        nonce: _,
        retries,
    })) = local.state
    {
        assert_eq!(retries, 0isize);
    } else {
        unreachable!();
    };

    // send Ping
    remote
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // verify remote state
    if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
        nonce: _,
        retries,
    })) = remote.state
    {
        assert_eq!(retries, 0isize);
    } else {
        unreachable!();
    };

    // read remote peer's Ping from socket and respond with Pong
    // save local peer's Ping to a temporary variable
    let msg = local.socket.recv().await;
    let ping: Message = remote.socket.recv().await.unwrap();
    assert_eq!(local.on_peer_event(msg).await, Ok(()));

    // read Pong from socket and verify state
    let msg = remote.socket.recv().await;
    assert_eq!(remote.on_peer_event(msg).await, Ok(()));

    // verify local and remote states
    assert_eq!(
        remote.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
        nonce: _,
        retries,
    })) = local.state
    {
        assert_eq!(retries, 0isize);
    } else {
        unreachable!();
    };

    // respond to local peer's Ping and read the response
    assert_eq!(remote.on_peer_event(Ok(ping)).await, Ok(()));

    let msg = local.socket.recv().await;
    assert_eq!(local.on_peer_event(msg).await, Ok(()));

    // once again verify local and remote states
    assert_eq!(
        remote.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    assert_eq!(
        local.state,
        PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PongReceived
        ))
    );

    // manually trigger `PingRetry` event for local and remote
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: PING_MAX_RETRIES,
        }))
        .await
        .unwrap();
    remote
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: PING_MAX_RETRIES,
        }))
        .await
        .unwrap();

    // finally verify that both peers are back to listening the socket normally
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));
}

// Send Pong and then another Pong right after
#[tokio::test]
async fn test_duplicate_pong() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // send Ping
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    // verify local state
    let nonce =
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

    // send Pong two times and verify that it doens't cause an error
    // but only changes the local node state to `PongReceived`
    for _ in 0..2 {
        remote
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce }),
            })
            .await
            .unwrap();

        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));
        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );
    }

    // finally verify that the state is back to `ListeningState::Any`
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
            max_retries: PING_MAX_RETRIES,
        }))
        .await
        .unwrap();
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

// Verify that recent activity on the socket cancels the schedule Ping
#[tokio::test]
async fn test_socket_activity() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, remote) = create_two_peers(Arc::clone(&config)).await;

    // verify that handshake was successful
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    local.last_activity = time::get();

    // try to send Ping and verify that because last activity on the socket was
    // less than 60 seconds ago, Ping is not sent
    local
        .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
        .await
        .unwrap();

    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
}

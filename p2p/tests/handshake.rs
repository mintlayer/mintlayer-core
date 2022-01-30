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
#![cfg(not(loom))]

use common::{
    chain::{config, ChainConfig},
    primitives::{time, version::SemVer},
};
use p2p::{
    error::{P2pError, ProtocolError},
    message::*,
    net::{
        mock::{MockService, MockSocket},
        Event, NetworkService, SocketService,
    },
    peer::{ListeningState, Peer, PeerRole, PeerState},
    proto::handshake::*,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;

async fn create_two_peers(
    local_config: Arc<ChainConfig>,
    remote_config: Arc<ChainConfig>,
) -> (Peer<MockService>, Peer<MockService>) {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let mut server = MockService::new(addr, &[], &[]).await.unwrap();
    let peer_fut = TcpStream::connect(addr);

    let (remote_res, local_res) = tokio::join!(server.poll_next(), peer_fut);
    let remote_res: Event<MockService> = remote_res.unwrap();
    let Event::IncomingConnection(remote_res) = remote_res;
    let local_res = local_res.unwrap();

    let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_tx2, rx2) = tokio::sync::mpsc::channel(1);

    let local = Peer::<MockService>::new(
        1,
        PeerRole::Outbound,
        Arc::clone(&local_config),
        remote_res,
        peer_tx.clone(),
        rx,
    );

    let remote = Peer::<MockService>::new(
        2,
        PeerRole::Inbound,
        Arc::clone(&remote_config),
        MockSocket::new(local_res),
        peer_tx,
        rx2,
    );

    (local, remote)
}

// Test that compatible nodes are able to handshake successfully
#[tokio::test]
async fn test_handshake_success() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    // verify initial state
    assert_eq!(local.role, PeerRole::Outbound);
    assert_eq!(remote.role, PeerRole::Inbound);
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    // send valid hello
    let res = local
        .on_handshake_event(
            HandshakeState::Outbound(OutboundHandshakeState::Initiate),
            HandshakeMessage::Hello {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            },
        )
        .await;

    // verify state and call result
    assert!(res.is_ok());
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(
            OutboundHandshakeState::WaitResponse
        ))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    // read responder socket and parse message
    let msg = remote.socket.recv().await;
    let res = remote.on_peer_event(msg).await;

    // verify state and call result
    assert!(res.is_ok());
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(
            OutboundHandshakeState::WaitResponse
        ))
    );
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

    // read initiator socket and parse message
    let msg = local.socket.recv().await;
    let res = local.on_peer_event(msg).await;

    assert!(res.is_ok());
    assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));
}

// Test that invalid magic number closes the connection
#[tokio::test]
async fn test_handshake_invalid_magic() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    // verify initial state
    assert_eq!(local.role, PeerRole::Outbound);
    assert_eq!(remote.role, PeerRole::Inbound);
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    // send valid hello with incompatible magic value
    local
        .socket
        .send(&Message {
            magic: [0xde, 0xad, 0xbe, 0xef],
            msg: MessageType::Handshake(HandshakeMessage::Hello {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            }),
        })
        .await
        .unwrap();

    // read responder socket and parse message
    let msg = remote.socket.recv().await;
    let res = remote.on_peer_event(msg).await;

    // verify that `res` is error and protocol error is reported
    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork))
    );

    // simulate remote node closing the connection and verify that
    // the read operation causes a protocol error to be returned
    drop(remote);
    let msg = local.socket.recv().await;
    let res = local.on_peer_event(msg).await;

    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::Incompatible))
    );
}

// Test that invalid version number closes the connection
#[tokio::test]
async fn test_handshake_invalid_version() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    // verify initial state
    assert_eq!(local.role, PeerRole::Outbound);
    assert_eq!(remote.role, PeerRole::Inbound);
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    // send valid hello with incompatible version
    local
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::Hello {
                version: SemVer::new(13, 37, 1338),
                services: 0u32,
                timestamp: time::get(),
            }),
        })
        .await
        .unwrap();

    // read responder socket and parse message
    let msg = remote.socket.recv().await;
    let res = remote.on_peer_event(msg).await;

    // verify that `res` is error and protocol error is reported
    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::InvalidVersion))
    );

    // simulate remote node closing the connection and verify that
    // the read operation causes a protocol error to be returned
    drop(remote);
    let msg = local.socket.recv().await;
    let res = local.on_peer_event(msg).await;

    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::Incompatible))
    );
}

// Outbound sends Hello to an incompatible responder who responds anyway with HelloACk
#[tokio::test]
async fn test_handshake_invalid_ack_sent() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    // verify initial state
    assert_eq!(local.role, PeerRole::Outbound);
    assert_eq!(remote.role, PeerRole::Inbound);
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    // send valid hello with incompatible version
    local
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::Hello {
                version: SemVer::new(13, 37, 1338),
                services: 0u32,
                timestamp: time::get(),
            }),
        })
        .await
        .unwrap();

    // read responder socket and parse message
    let msg = remote.socket.recv().await;
    let res = remote.on_peer_event(msg).await;

    // verify that `res` is error and protocol error is reported
    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::InvalidVersion))
    );

    // simulate remote node closing the connection and verify that
    // the received HelloAck is rejected as it should be
    drop(local);
    let msg = remote.socket.recv().await;
    let res = remote.on_peer_event(msg).await;
    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::Incompatible))
    );
}

// Outbound sends Hello but responder sends something other than HelloAck
#[tokio::test]
async fn test_handshake_ack_not_sent() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    // verify initial state
    assert_eq!(local.role, PeerRole::Outbound);
    assert_eq!(remote.role, PeerRole::Inbound);
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    // send valid hello
    let res = local
        .on_handshake_event(
            HandshakeState::Outbound(OutboundHandshakeState::Initiate),
            HandshakeMessage::Hello {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            },
        )
        .await;

    // verify state and call result
    assert!(res.is_ok());
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(
            OutboundHandshakeState::WaitResponse
        ))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    remote
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::Hello {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            }),
        })
        .await
        .unwrap();

    // read initiator socket and parse message
    let msg = local.socket.recv().await;
    let res = local.on_peer_event(msg).await;

    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
    );
}

// Outbound doesn't start the connection by handshaking but sends something else
#[tokio::test]
async fn test_handshake_hello_not_sent() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, mut remote) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    // verify initial state
    assert_eq!(local.role, PeerRole::Outbound);
    assert_eq!(remote.role, PeerRole::Inbound);
    assert_eq!(
        local.state,
        PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
    );
    assert_eq!(
        remote.state,
        PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation
        ))
    );

    // send valid HelloAck but it's considered invalid because initiator is expected to send Hello
    local
        .socket
        .send(&Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            }),
        })
        .await
        .unwrap();

    // read responder socket and parse message
    let msg = remote.socket.recv().await;
    let res = remote.on_peer_event(msg).await;

    // verify that `res` is error and protocol error is reported
    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
    );

    // simulate remote node closing the connection and verify that
    // the read operation causes a protocol error to be returned
    drop(remote);
    let msg = local.socket.recv().await;
    let res = local.on_peer_event(msg).await;

    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::Incompatible))
    );
}

// try to initiate with helloack
#[tokio::test]
async fn test_initiate_with_helloack() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, _) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    local.role = PeerRole::Outbound;
    local.state =
        PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate));

    let res = local
        .on_peer_event(Ok(Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            }),
        }))
        .await;

    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
    );
}

// outbound tried to initiate with helloack
#[tokio::test]
async fn test_inbound_reject_helloack() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, _) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    local.role = PeerRole::Inbound;
    local.state = PeerState::Handshaking(HandshakeState::Inbound(
        InboundHandshakeState::WaitInitiation,
    ));

    let res = local
        .on_peer_event(Ok(Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            }),
        }))
        .await;

    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
    );
}

// inbound responded to hello with hello
#[tokio::test]
async fn test_outbound_reject_hello() {
    let config = Arc::new(config::create_mainnet());
    let (mut local, _) = create_two_peers(Arc::clone(&config), Arc::clone(&config)).await;

    local.role = PeerRole::Outbound;
    local.state = PeerState::Handshaking(HandshakeState::Outbound(
        OutboundHandshakeState::WaitResponse,
    ));

    let res = local
        .on_peer_event(Ok(Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::Hello {
                version: *config.version(),
                services: 0u32,
                timestamp: time::get(),
            }),
        }))
        .await;

    assert_eq!(
        res,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
    );
}

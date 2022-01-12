// Copyright (c) 2021 RBB S.r.l
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
use crate::error::{self, P2pError, ProtocolError};
use crate::message::{HandshakeMessage, Message, MessageType};
use crate::net::{NetworkService, SocketService};
use crate::peer::{ListeningState, Peer, PeerState};
use common::primitives::time;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InboundHandshakeState {
    /// Wait for Hello message
    WaitInitiation,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OutboundHandshakeState {
    /// Send Hello message
    Initiate,

    /// Wait for HelloAck message
    WaitResponse,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Handshake state for the inbound peer
    Inbound(InboundHandshakeState),

    /// Handshake state for the outbound peer
    Outbound(OutboundHandshakeState),
}

#[allow(unused)]
impl<NetworkingBackend> Peer<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Handle handshake event for inbound peer
    ///
    /// The inbound peer has only only one state in which the received Hello is parsed
    /// and if it's valid, the peer proceeds to listening further messages and if it's
    /// invalid, the connection is closed.
    ///
    /// If HelloAck is received instead, the connection is closed due to protocol error
    /// and `P2pError::ProtocolError` is returned.
    ///
    /// If remote closed the socket, indicating protocol error, `P2pError::SocketError`
    /// is returned
    async fn on_inbound_handshake_event(
        &mut self,
        state: InboundHandshakeState,
        msg: HandshakeMessage,
    ) -> error::Result<()> {
        match (state, msg) {
            (InboundHandshakeState::WaitInitiation, HandshakeMessage::Hello { version, .. }) => {
                if version != *self.config.version() {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidVersion));
                }

                let msg = Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                        version: *self.config.version(),
                        services: 0u32,
                        timestamp: time::get(),
                    }),
                };

                self.socket.send(&msg).await?;
                self.state = PeerState::Listening(ListeningState::Any);
                return Ok(());
            }
            (InboundHandshakeState::WaitInitiation, HandshakeMessage::HelloAck { .. }) => {
                return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
            }
        }

        panic!("Invalid state/message combination");
    }

    /// Handle handshake event for outbound peer
    ///
    /// The outbound peer has two states: the state where it sends the Hello message
    /// to remote peer and the state where the HelloAck is received and validated.
    /// If the HelloAck indicates that the peers are compatible, the outbound peer
    /// concludes the handshake and proceeds to listen to further messages from the peer.
    ///
    /// All other states are considered protocols errors and `P2pError::ProtocolError`
    /// is returned.
    ///
    /// If remote closed the socket, indicating a protocol error, `P2pError::SocketError`
    /// is returned
    async fn on_outbound_handshake_event(
        &mut self,
        state: OutboundHandshakeState,
        msg: HandshakeMessage,
    ) -> error::Result<()> {
        match (state, msg) {
            (OutboundHandshakeState::Initiate, HandshakeMessage::Hello { .. }) => {
                self.socket
                    .send(&Message {
                        magic: *self.config.magic_bytes(),
                        msg: MessageType::Handshake(msg),
                    })
                    .await?;

                self.state = PeerState::Handshaking(HandshakeState::Outbound(
                    OutboundHandshakeState::WaitResponse,
                ));
                return Ok(());
            }
            (OutboundHandshakeState::WaitResponse, HandshakeMessage::HelloAck { version, .. }) => {
                if version != *self.config.version() {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                }

                self.state = PeerState::Listening(ListeningState::Any);
                return Ok(());
            }
            (OutboundHandshakeState::WaitResponse, HandshakeMessage::Hello { .. }) => {
                return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
            }
            (OutboundHandshakeState::Initiate, HandshakeMessage::HelloAck { .. }) => {
                return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
            }
        }

        panic!("Invalid state/message combination");
    }

    /// Handle handshake event
    ///
    /// Peer has an active handshake going on and it has received a handshake event from remote
    /// As the handshaking procedure is different based on the role of the peer, branch out
    /// to separate functions to handle handshaking based on whether peer is the inbound
    /// or outbound participant of the connection.
    ///
    /// This function may return `P2pError::ProtocolError` which means that there was
    /// an invalid peer state/message combination or it may return `P2pError::SocketError`
    /// indicating that the remote peer closed the connection during handshaking.
    ///
    /// This function assumes that the magic number of the message has been verified
    /// and sender and the local node are using the same chain type (Mainnet, Testnet)
    pub async fn on_handshake_event(
        &mut self,
        state: HandshakeState,
        msg: HandshakeMessage,
    ) -> error::Result<()> {
        match state {
            HandshakeState::Inbound(state) => self.on_inbound_handshake_event(state, msg).await,
            HandshakeState::Outbound(state) => self.on_outbound_handshake_event(state, msg).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::{MockService, MockSocket};
    use crate::peer::PeerRole;
    use common::chain::{config, ChainConfig};
    use common::primitives::time;
    use common::primitives::version::SemVer;
    use std::sync::Arc;
    use tokio::net::TcpStream;

    async fn create_two_peers(
        local_config: Arc<ChainConfig>,
        remote_config: Arc<ChainConfig>,
        addr: std::net::SocketAddr,
    ) -> (Peer<MockService>, Peer<MockService>) {
        let mut server = MockService::new(addr).await.unwrap();
        let peer_fut = TcpStream::connect(addr);

        let (remote_res, local_res) = tokio::join!(server.accept(), peer_fut);
        let remote_res = remote_res.unwrap();
        let local_res = local_res.unwrap();

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let (_tx2, rx2) = tokio::sync::mpsc::channel(1);

        let local = Peer::<MockService>::new(
            1,
            PeerRole::Outbound,
            local_config.clone(),
            remote_res,
            peer_tx.clone(),
            rx,
        );

        let remote = Peer::<MockService>::new(
            2,
            PeerRole::Inbound,
            remote_config.clone(),
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
        let addr = "[::1]:11122".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11123".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11124".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11125".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11126".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11127".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11128".parse().unwrap();
        let (mut local, _) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11129".parse().unwrap();
        let (mut local, _) = create_two_peers(config.clone(), config.clone(), addr).await;

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
        let addr = "[::1]:11130".parse().unwrap();
        let (mut local, _) = create_two_peers(config.clone(), config.clone(), addr).await;

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
}

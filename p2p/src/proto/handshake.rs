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
use crate::{
    error::{self, P2pError, ProtocolError},
    event::{PeerEvent, PeerEventType},
    message::{HandshakeMessage, Message, MessageType},
    net::{NetworkService, SocketService},
    peer::{ListeningState, Peer, PeerState},
};
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
                self.mgr_tx
                    .send(PeerEvent {
                        peer_id: self.id,
                        event: PeerEventType::HandshakeSucceeded,
                    })
                    .await?;
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

                self.mgr_tx
                    .send(PeerEvent {
                        peer_id: self.id,
                        event: PeerEventType::HandshakeSucceeded,
                    })
                    .await?;
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
        let res = match state {
            HandshakeState::Inbound(state) => self.on_inbound_handshake_event(state, msg).await,
            HandshakeState::Outbound(state) => self.on_outbound_handshake_event(state, msg).await,
        };

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                self.mgr_tx
                    .send(PeerEvent {
                        peer_id: self.id,
                        event: PeerEventType::HandshakeFailed,
                    })
                    .await?;
                Err(e)
            }
        }
    }

    /// Handle inboud message when local peer is handshaking
    pub async fn on_handshake_state_peer_event(
        &mut self,
        state: HandshakeState,
        msg: Message,
    ) -> error::Result<()> {
        match msg.msg {
            MessageType::Handshake(msg) => {
                // found in src/proto/handshake.rs
                self.on_handshake_event(state, msg).await
            }
            MessageType::Connectivity(_) => {
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        message::*,
        net::mock::{MockService, MockSocket},
        peer::PeerRole,
    };
    use common::{chain::config, primitives::version::SemVer};
    use std::sync::Arc;

    // make a mock service peer
    async fn make_peer() -> Peer<MockService> {
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(1);
        let (_, rx) = tokio::sync::mpsc::channel(1);

        // spawn dummy task that listens to the peer RX channel and
        // acts as though a P2P object was listening to events from the peer
        tokio::spawn(async move {
            loop {
                let _ = peer_rx.recv().await;
            }
        });

        Peer::<MockService>::new(
            1,
            PeerRole::Inbound,
            Arc::new(config::create_mainnet()),
            MockSocket::new(test_utils::get_tcp_socket().await),
            peer_tx,
            rx,
        )
    }

    #[tokio::test]
    async fn test_handshake_state_peer_event() {
        let mut peer = make_peer().await;

        assert_eq!(
            peer.on_handshake_state_peer_event(
                HandshakeState::Inbound(InboundHandshakeState::WaitInitiation),
                Message {
                    magic: [1, 2, 3, 4],
                    msg: MessageType::Connectivity(ConnectivityMessage::Ping { nonce: u64::MAX })
                }
            )
            .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
        );
    }

    #[tokio::test]
    async fn test_handshake_outbound_handshake_event() {
        let mut peer = make_peer().await;

        // verify that valid combination succeeds
        assert_eq!(
            peer.on_outbound_handshake_event(
                OutboundHandshakeState::Initiate,
                HandshakeMessage::Hello {
                    version: SemVer::new(0, 1, 0),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Ok(())
        );
        assert_eq!(
            peer.state,
            PeerState::Handshaking(HandshakeState::Outbound(
                OutboundHandshakeState::WaitResponse,
            ))
        );

        // invalid version in helloack
        assert_eq!(
            peer.on_outbound_handshake_event(
                OutboundHandshakeState::WaitResponse,
                HandshakeMessage::HelloAck {
                    version: SemVer::new(1, 2, 3),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );

        // valid helloack
        assert_eq!(
            peer.on_outbound_handshake_event(
                OutboundHandshakeState::WaitResponse,
                HandshakeMessage::HelloAck {
                    version: *peer.config.version(),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Ok(()),
        );
        assert_eq!(peer.state, PeerState::Listening(ListeningState::Any));

        // invalid state/message combination
        assert_eq!(
            peer.on_outbound_handshake_event(
                OutboundHandshakeState::WaitResponse,
                HandshakeMessage::Hello {
                    version: SemVer::new(1, 2, 3),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );

        // invalid state/message combination
        assert_eq!(
            peer.on_outbound_handshake_event(
                OutboundHandshakeState::Initiate,
                HandshakeMessage::HelloAck {
                    version: SemVer::new(1, 2, 3),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );
    }

    #[tokio::test]
    async fn test_handshake_inbound_handshake_event() {
        let mut peer = make_peer().await;

        // invalid state/message combination
        assert_eq!(
            peer.on_inbound_handshake_event(
                InboundHandshakeState::WaitInitiation,
                HandshakeMessage::HelloAck {
                    version: SemVer::new(1, 2, 3),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );

        // invalid version
        assert_eq!(
            peer.on_inbound_handshake_event(
                InboundHandshakeState::WaitInitiation,
                HandshakeMessage::Hello {
                    version: SemVer::new(1, 2, 3),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidVersion)),
        );

        // valid state/message combination
        assert_eq!(
            peer.on_inbound_handshake_event(
                InboundHandshakeState::WaitInitiation,
                HandshakeMessage::Hello {
                    version: *peer.config.version(),
                    services: u32::MAX,
                    timestamp: i64::MAX,
                }
            )
            .await,
            Ok(()),
        );
        assert_eq!(peer.state, PeerState::Listening(ListeningState::Any));
    }
}

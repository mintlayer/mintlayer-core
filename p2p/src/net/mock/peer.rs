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
    message,
    net::mock::{
        socket,
        types::{self, MockEvent, MockPeerId, PeerEvent},
    },
};
use common::chain::config;
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

pub enum Role {
    Inbound,
    Outbound,
}

pub struct Peer {
    peer_id: MockPeerId,
    role: Role,
    config: Arc<config::ChainConfig>,
    socket: socket::MockSocket,
    tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
    rx: mpsc::Receiver<MockEvent>,
}

impl Peer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_id: MockPeerId,
        role: Role,
        config: Arc<config::ChainConfig>,
        socket: socket::MockSocket,
        tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
        rx: mpsc::Receiver<MockEvent>,
    ) -> Self {
        Self {
            peer_id,
            role,
            config,
            socket,
            tx,
            rx,
        }
    }

    // TODO: move to a separate file
    async fn handshake(&mut self) -> error::Result<()> {
        match self.role {
            Role::Inbound => {
                let (net, version, protocols) =
                    if let Ok(Some(types::Message::Handshake(types::HandshakeMessage::Hello {
                        version,
                        network,
                        protocols,
                    }))) = self.socket.recv().await
                    {
                        if &network != self.config.magic_bytes() {
                            return Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork));
                        }

                        (
                            common::chain::config::ChainType::Mainnet,
                            version,
                            protocols,
                        )
                    } else {
                        return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                    };

                self.socket
                    .send(types::Message::Handshake(
                        types::HandshakeMessage::HelloAck {
                            version: *self.config.version(),
                            network: *self.config.magic_bytes(),
                            protocols: vec![
                                types::Protocol::new("floodsub", *self.config.version()),
                                types::Protocol::new("ping", *self.config.version()),
                            ],
                        },
                    ))
                    .await?;

                self.tx
                    .send((
                        self.peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            net,
                            version,
                            protocols,
                        },
                    ))
                    .await
                    .map_err(P2pError::from)
            }
            Role::Outbound => {
                self.socket
                    .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                        version: *self.config.version(),
                        network: *self.config.magic_bytes(),
                        protocols: vec![
                            types::Protocol::new("floodsub", *self.config.version()),
                            types::Protocol::new("ping", *self.config.version()),
                        ],
                    }))
                    .await?;

                let (net, version, protocols) = if let Ok(Some(types::Message::Handshake(
                    types::HandshakeMessage::HelloAck {
                        version,
                        network,
                        protocols,
                    },
                ))) = self.socket.recv().await
                {
                    if &network != self.config.magic_bytes() {
                        return Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork));
                    }

                    (
                        common::chain::config::ChainType::Mainnet,
                        version,
                        protocols,
                    )
                } else {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                };

                self.tx
                    .send((
                        self.peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            net,
                            version,
                            protocols,
                        },
                    ))
                    .await
                    .map_err(P2pError::from)
            }
        }
    }

    pub async fn start(&mut self) -> error::Result<()> {
        // handshake with remote peer and send peer's info to backend
        if let Err(e) = self.handshake().await {
            // TODO: inform backend
        }

        loop {
            tokio::select! {
                event = self.rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    MockEvent::Disconnect => break,
                    MockEvent::SendMessage(message) => self.socket.send(*message).await?,
                },
                message = self.socket.recv() => match message {
                    Ok(Some(message)) => {
                        self.tx.send((
                            self.peer_id,
                            types::PeerEvent::MessageReceived { message }
                        )).await?;
                    },
                    Ok(None) => {
                        log::warn!("connection closed");
                        // TODO: inform backend
                    },
                    Err(e) => {
                        log::warn!("error with connection: {:?}", e);
                        // TODO: inform backend
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::socket;
    use futures::FutureExt;

    #[tokio::test]
    async fn handshake_inbound() {
        let (socket1, socket2) = test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);
        let peer_id = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id,
            Role::Inbound,
            Arc::clone(&config),
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move {
            peer.handshake().await.unwrap();
            peer
        });

        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                version: *config.version(),
                network: *config.magic_bytes(),
                protocols: vec![
                    types::Protocol::new("floodsub", *config.version()),
                    types::Protocol::new("ping", *config.version()),
                ],
            }))
            .await
            .is_ok());

        let peer = handle.await;
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id,
                types::PeerEvent::PeerInfoReceived {
                    net: common::chain::config::ChainType::Mainnet,
                    version: *config.version(),
                    protocols: vec![
                        types::Protocol::new("floodsub", *config.version()),
                        types::Protocol::new("ping", *config.version()),
                    ]
                }
            ))
        );
    }

    #[tokio::test]
    async fn handshake_outbound() {
        let (socket1, socket2) = test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);
        let peer_id = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id,
            Role::Outbound,
            Arc::clone(&config),
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move {
            peer.handshake().await.unwrap();
            peer
        });

        if let Some(message) = socket2.recv().await.unwrap() {
            assert!(socket2
                .send(types::Message::Handshake(
                    types::HandshakeMessage::HelloAck {
                        version: *config.version(),
                        network: *config.magic_bytes(),
                        protocols: vec![
                            types::Protocol::new("floodsub", *config.version()),
                            types::Protocol::new("ping", *config.version()),
                        ],
                    }
                ))
                .await
                .is_ok());
        }

        let peer = handle.await;
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id,
                types::PeerEvent::PeerInfoReceived {
                    net: common::chain::config::ChainType::Mainnet,
                    version: *config.version(),
                    protocols: vec![
                        types::Protocol::new("floodsub", *config.version()),
                        types::Protocol::new("ping", *config.version()),
                    ]
                }
            ))
        );
    }

    #[tokio::test]
    async fn handshake_different_network() {
        let (socket1, socket2) = test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);
        let peer_id = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id,
            Role::Inbound,
            Arc::clone(&config),
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move { peer.handshake().await });

        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                version: *config.version(),
                network: [1, 2, 3, 4],
                protocols: vec![
                    types::Protocol::new("floodsub", *config.version()),
                    types::Protocol::new("ping", *config.version()),
                ],
            }))
            .await
            .is_ok());

        assert_eq!(
            handle.await.unwrap(),
            Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork))
        );
        assert_eq!(
            rx1.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        );
    }

    #[tokio::test]
    async fn disconnect() {
        let (socket1, socket2) = test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);
        let peer_id = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id,
            Role::Inbound,
            Arc::clone(&config),
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move { peer.start().await });

        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                version: *config.version(),
                network: *config.magic_bytes(),
                protocols: vec![
                    types::Protocol::new("floodsub", *config.version()),
                    types::Protocol::new("ping", *config.version()),
                ],
            }))
            .await
            .is_ok());

        assert_eq!(
            tx2.send(MockEvent::Disconnect).await.map_err(P2pError::from),
            Ok(())
        );
        assert_eq!(handle.await.unwrap(), Ok(()));
    }
}

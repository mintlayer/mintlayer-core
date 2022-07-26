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
    error::{P2pError, ProtocolError},
    net::mock::{
        socket,
        types::{self, MockEvent, MockPeerId, PeerEvent},
    },
};
use common::chain::ChainConfig;
use futures::FutureExt;
use std::sync::Arc;
use tokio::sync::mpsc;

pub enum Role {
    Inbound,
    Outbound,
}

pub struct Peer {
    peer_id: MockPeerId,
    config: Arc<ChainConfig>,
    role: Role,
    socket: socket::MockSocket,
    tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
    rx: mpsc::Receiver<MockEvent>,
}

impl Peer {
    pub fn new(
        peer_id: MockPeerId,
        role: Role,
        config: Arc<ChainConfig>,
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

    async fn handshake(&mut self) -> crate::Result<()> {
        match self.role {
            Role::Inbound => {
                let (network, version, protocols) =
                    if let Ok(Some(types::Message::Handshake(types::HandshakeMessage::Hello {
                        version,
                        network,
                        protocols,
                    }))) = self.socket.recv().await
                    {
                        if &network != self.config.magic_bytes() {
                            return Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork(
                                network,
                                *self.config.magic_bytes(),
                            )));
                        }

                        (network, version, protocols)
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
                            network,
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

                let (network, version, protocols) = if let Ok(Some(types::Message::Handshake(
                    types::HandshakeMessage::HelloAck {
                        version,
                        network,
                        protocols,
                    },
                ))) = self.socket.recv().await
                {
                    if &network != self.config.magic_bytes() {
                        return Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork(
                            network,
                            *self.config.magic_bytes(),
                        )));
                    }

                    (network, version, protocols)
                } else {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                };

                self.tx
                    .send((
                        self.peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            network,
                            version,
                            protocols,
                        },
                    ))
                    .await
                    .map_err(P2pError::from)
            }
        }
    }

    pub async fn start(&mut self) -> crate::Result<()> {
        // handshake with remote peer and send peer's info to backend
        if let Err(_err) = self.handshake().await {
            // TODO: inform backend
        }

        loop {
            tokio::select! {
                event = self.rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    MockEvent::Dummy => {
                        todo!();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net::mock::socket;
    use futures::FutureExt;

    #[tokio::test]
    async fn handshake_inbound() {
        let (socket1, socket2) = p2p_test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
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

        let _peer = handle.await;
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id,
                types::PeerEvent::PeerInfoReceived {
                    network: *config.magic_bytes(),
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
        let (socket1, socket2) = p2p_test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
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

        if let Some(_message) = socket2.recv().await.unwrap() {
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

        let _peer = handle.await;
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id,
                types::PeerEvent::PeerInfoReceived {
                    network: *config.magic_bytes(),
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
        let (socket1, socket2) = p2p_test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
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
            Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork(
                [1, 2, 3, 4],
                *config.magic_bytes()
            )))
        );
        assert_eq!(
            rx1.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        );
    }
}

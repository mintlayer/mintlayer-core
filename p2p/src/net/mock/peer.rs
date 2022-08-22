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

use std::sync::Arc;

use futures::FutureExt;
use tokio::sync::mpsc;

use common::{chain::ChainConfig, primitives::semver::SemVer};
use logging::log;

use crate::{
    error::{P2pError, ProtocolError},
    net::{
        mock::{
            socket,
            types::{self, MockEvent, MockPeerId, PeerEvent},
        },
        types::{Protocol, ProtocolType},
    },
};

pub enum Role {
    Inbound,
    Outbound,
}

pub struct Peer {
    /// Peer ID of the local node
    local_peer_id: MockPeerId,

    /// Peer ID of the remote node
    remote_peer_id: MockPeerId,

    /// Chain config
    config: Arc<ChainConfig>,

    /// Is the connection inbound or outbound
    role: Role,

    /// Peer socket
    socket: socket::MockSocket,

    /// TX channel for communicating with backend
    tx: mpsc::Sender<(MockPeerId, PeerEvent)>,

    /// RX channel for receiving commands from backend
    rx: mpsc::Receiver<MockEvent>,
}

impl Peer {
    pub fn new(
        local_peer_id: MockPeerId,
        remote_peer_id: MockPeerId,
        role: Role,
        config: Arc<ChainConfig>,
        socket: socket::MockSocket,
        tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
        rx: mpsc::Receiver<MockEvent>,
    ) -> Self {
        Self {
            local_peer_id,
            remote_peer_id,
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
                let (peer_id, network, version, protocols) =
                    if let Ok(Some(types::Message::Handshake(types::HandshakeMessage::Hello {
                        peer_id,
                        version,
                        network,
                        protocols,
                    }))) = self.socket.recv().await
                    {
                        (peer_id, network, version, protocols)
                    } else {
                        return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                    };

                self.socket
                    .send(types::Message::Handshake(
                        types::HandshakeMessage::HelloAck {
                            peer_id: self.local_peer_id,
                            version: *self.config.version(),
                            network: *self.config.magic_bytes(),
                            // TODO: Replace the hard-coded values when ping and pubsub protocols are implemented for the mock interface.
                            protocols: [
                                Protocol::new(ProtocolType::PubSub, SemVer::new(0, 1, 0)),
                                Protocol::new(ProtocolType::Ping, SemVer::new(0, 1, 0)),
                            ]
                            .into_iter()
                            .collect(),
                        },
                    ))
                    .await?;

                self.tx
                    .send((
                        self.remote_peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            peer_id,
                            network,
                            version,
                            protocols,
                        },
                    ))
                    .await
                    .map_err(P2pError::from)?;

                self.remote_peer_id = peer_id;
                Ok(())
            }
            Role::Outbound => {
                self.socket
                    .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                        peer_id: self.local_peer_id,
                        version: *self.config.version(),
                        network: *self.config.magic_bytes(),
                        protocols: [
                            Protocol::new(ProtocolType::PubSub, *self.config.version()),
                            Protocol::new(ProtocolType::Ping, *self.config.version()),
                        ]
                        .into_iter()
                        .collect(),
                    }))
                    .await?;

                let (peer_id, network, version, protocols) = if let Ok(Some(
                    types::Message::Handshake(types::HandshakeMessage::HelloAck {
                        peer_id,
                        version,
                        network,
                        protocols,
                    }),
                )) = self.socket.recv().await
                {
                    (peer_id, network, version, protocols)
                } else {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                };

                self.tx
                    .send((
                        self.remote_peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            peer_id,
                            network,
                            version,
                            protocols,
                        },
                    ))
                    .await
                    .map_err(P2pError::from)?;

                self.remote_peer_id = peer_id;
                Ok(())
            }
        }
    }

    async fn destroy_peer(&mut self) -> crate::Result<()> {
        self.tx
            .send((self.remote_peer_id, types::PeerEvent::ConnectionClosed))
            .await
            .map_err(P2pError::from)
    }

    pub async fn start(&mut self) -> crate::Result<()> {
        // handshake with remote peer and send peer's info to backend
        if let Err(err) = self.handshake().await {
            log::debug!("handshake failed for peer {}: {err}", self.remote_peer_id);
            return self.destroy_peer().await;
        }

        loop {
            tokio::select! {
                event = self.rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    MockEvent::Disconnect => return self.destroy_peer().await,
                },
                event = self.socket.recv() => match event {
                    Err(err) => {
                        log::info!("peer connection closed, reason {err}");
                        self.destroy_peer().await?;
                    }
                    Ok(None) => self.destroy_peer().await?,
                    Ok(Some(_event)) => {
                        // TODO: handle message
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{message, net::mock::socket};
    use chainstate::Locator;
    use common::primitives::semver::SemVer;
    use futures::FutureExt;

    #[tokio::test]
    async fn handshake_inbound() {
        let (socket1, socket2) = p2p_test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id1,
            peer_id3,
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
                peer_id: peer_id2,
                version: *config.version(),
                network: *config.magic_bytes(),
                protocols: [
                    Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
                    Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                ]
                .into_iter()
                .collect(),
            }))
            .await
            .is_ok());

        let _peer = handle.await;
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id3,
                types::PeerEvent::PeerInfoReceived {
                    peer_id: peer_id2,
                    network: *config.magic_bytes(),
                    version: *config.version(),
                    protocols: [
                        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                    ]
                    .into_iter()
                    .collect(),
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
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id1,
            peer_id3,
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
                        peer_id: peer_id2,
                        version: *config.version(),
                        network: *config.magic_bytes(),
                        protocols: [
                            Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
                            Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                        ]
                        .into_iter()
                        .collect(),
                    }
                ))
                .await
                .is_ok());
        }

        let _peer = handle.await;
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id3,
                types::PeerEvent::PeerInfoReceived {
                    peer_id: peer_id2,
                    network: *config.magic_bytes(),
                    version: *config.version(),
                    protocols: [
                        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                    ]
                    .into_iter()
                    .collect(),
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
        let (tx1, _rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id1,
            peer_id3,
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
                peer_id: peer_id2,
                version: *config.version(),
                network: [1, 2, 3, 4],
                protocols: [
                    Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
                    Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                ]
                .into_iter()
                .collect(),
            }))
            .await
            .is_ok());

        assert_eq!(handle.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn invalid_handshake_message() {
        let (socket1, socket2) = p2p_test_utils::get_two_connected_sockets().await;
        let socket1 = socket::MockSocket::new(socket1);
        let mut socket2 = socket::MockSocket::new(socket2);
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, _rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();

        let mut peer = Peer::new(
            peer_id1,
            peer_id2,
            Role::Inbound,
            Arc::clone(&config),
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move { peer.handshake().await });

        assert!(socket2.recv().now_or_never().is_none());
        socket2
            .send(types::Message::Request(
                message::Request::HeaderListRequest(message::HeaderListRequest::new(Locator::new(
                    vec![],
                ))),
            ))
            .await
            .unwrap();

        assert_eq!(
            handle.await.unwrap(),
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );
    }
}

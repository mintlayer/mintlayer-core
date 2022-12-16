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

use std::{sync::Arc, time::Duration};

use tokio::{sync::mpsc, time::timeout};

use common::{chain::ChainConfig, primitives::semver::SemVer};
use logging::log;

use crate::{
    config::P2pConfig,
    error::{P2pError, ProtocolError},
    net::{
        mock::{
            transport::TransportSocket,
            types::{self, MockEvent, MockPeerId, PeerEvent},
        },
        types::{Protocol, ProtocolType},
    },
};

use super::transport::BufferedTranscoder;

const PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub enum Role {
    Inbound,
    Outbound,
}

pub struct Peer<T: TransportSocket> {
    /// Peer ID of the remote node
    peer_id: MockPeerId,

    /// Chain config
    chain_config: Arc<ChainConfig>,

    p2p_config: Arc<P2pConfig>,

    /// Is the connection inbound or outbound
    role: Role,

    /// Peer socket
    socket: BufferedTranscoder<T::Stream>,

    /// TX channel for communicating with backend
    tx: mpsc::Sender<(MockPeerId, PeerEvent)>,

    /// RX channel for receiving commands from backend
    rx: mpsc::Receiver<MockEvent>,
}

impl<T> Peer<T>
where
    T: TransportSocket,
{
    #![allow(clippy::too_many_arguments)]
    pub fn new(
        peer_id: MockPeerId,
        role: Role,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        socket: T::Stream,
        tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
        rx: mpsc::Receiver<MockEvent>,
    ) -> Self {
        let socket = BufferedTranscoder::new(socket);
        Self {
            peer_id,
            role,
            chain_config,
            p2p_config,
            socket,
            tx,
            rx,
        }
    }

    async fn handshake(&mut self) -> crate::Result<()> {
        match self.role {
            Role::Inbound => {
                let Ok(types::Message::Handshake(types::HandshakeMessage::Hello {
                    version,
                    network,
                    protocols,
                    subscriptions,
                })) = self.socket.recv().await
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                };

                self.socket
                    .send(types::Message::Handshake(
                        types::HandshakeMessage::HelloAck {
                            version: *self.chain_config.version(),
                            network: *self.chain_config.magic_bytes(),
                            // TODO: Replace the hard-coded values when ping and pubsub protocols are implemented for the mock interface.
                            protocols: [
                                Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                                Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                                Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                            ]
                            .into_iter()
                            .collect(),
                            subscriptions: (*self.p2p_config.node_type.as_ref()).into(),
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
                            subscriptions,
                        },
                    ))
                    .await
                    .map_err(P2pError::from)?;

                Ok(())
            }
            Role::Outbound => {
                self.socket
                    .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                        version: *self.chain_config.version(),
                        network: *self.chain_config.magic_bytes(),
                        protocols: [
                            Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                            Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                            Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                        ]
                        .into_iter()
                        .collect(),
                        subscriptions: (*self.p2p_config.node_type.as_ref()).into(),
                    }))
                    .await?;

                let Ok(types::Message::Handshake(types::HandshakeMessage::HelloAck {
                    version,
                    network,
                    protocols,
                    subscriptions,
                })) = self.socket.recv().await
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                };

                self.tx
                    .send((
                        self.peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            network,
                            version,
                            protocols,
                            subscriptions,
                        },
                    ))
                    .await
                    .map_err(P2pError::from)?;

                Ok(())
            }
        }
    }

    pub async fn destroy(self) {
        let _ = self.tx.send((self.peer_id, types::PeerEvent::ConnectionClosed)).await;
    }

    pub async fn run(&mut self) -> crate::Result<()> {
        // handshake with remote peer and send peer's info to backend
        let handshake_res = timeout(PEER_HANDSHAKE_TIMEOUT, self.handshake()).await;
        match handshake_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                log::debug!("handshake failed for peer {}: {err}", self.peer_id);
                return Err(err);
            }
            Err(_) => {
                log::debug!("handshake timeout for peer {}", self.peer_id);
                return Err(P2pError::ProtocolError(ProtocolError::Unresponsive));
            }
        }

        loop {
            tokio::select! {
                event = self.rx.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    MockEvent::Disconnect => return Ok(()),
                    MockEvent::SendMessage(message) => self.socket.send(*message).await?,
                },
                event = self.socket.recv() => match event {
                    Err(err) => {
                        log::info!("peer connection closed, reason {err:?}");
                        return Ok(());
                    }
                    Ok(message) => {
                        self.tx
                            .send((
                                self.peer_id,
                                types::PeerEvent::MessageReceived {
                                    message
                                },
                            ))
                            .await
                            .map_err(P2pError::from)?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_utils::{
        TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
    };
    use crate::{
        message,
        net::{
            mock::{
                transport::{
                    MockChannelTransport, NoiseTcpTransport, TcpTransportSocket, TransportListener,
                },
                types,
            },
            types::PubSubTopic,
        },
    };
    use chainstate::Locator;
    use common::primitives::semver::SemVer;
    use futures::FutureExt;

    async fn handshake_inbound<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(P2pConfig::default());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id2 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
            peer_id2,
            Role::Inbound,
            Arc::clone(&chain_config),
            p2p_config,
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move {
            peer.handshake().await.unwrap();
            peer
        });

        let mut socket2 = BufferedTranscoder::new(socket2);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                version: *chain_config.version(),
                network: *chain_config.magic_bytes(),
                protocols: [
                    Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                    Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                    Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                ]
                .into_iter()
                .collect(),
                subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                    .into_iter()
                    .collect(),
            }))
            .await
            .is_ok());

        let _peer = handle.await;
        assert_eq!(
            rx1.try_recv().unwrap().1,
            types::PeerEvent::PeerInfoReceived {
                network: *chain_config.magic_bytes(),
                version: *chain_config.version(),
                protocols: [
                    Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                    Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                    Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                ]
                .into_iter()
                .collect(),
                subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                    .into_iter()
                    .collect(),
            }
        );
    }

    #[tokio::test]
    async fn handshake_inbound_tcp() {
        handshake_inbound::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn handshake_inbound_channels() {
        handshake_inbound::<TestTransportChannel, MockChannelTransport>().await;
    }

    #[tokio::test]
    async fn handshake_inbound_noise() {
        handshake_inbound::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn handshake_outbound<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(P2pConfig::default());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
            peer_id3,
            Role::Outbound,
            Arc::clone(&chain_config),
            p2p_config,
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move {
            peer.handshake().await.unwrap();
            peer
        });

        let mut socket2 = BufferedTranscoder::new(socket2);
        socket2.recv().await.unwrap();
        assert!(socket2
            .send(types::Message::Handshake(
                types::HandshakeMessage::HelloAck {
                    version: *chain_config.version(),
                    network: *chain_config.magic_bytes(),
                    protocols: [
                        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                        Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                    ]
                    .into_iter()
                    .collect(),
                    subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                        .into_iter()
                        .collect(),
                }
            ))
            .await
            .is_ok());

        let _peer = handle.await;
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id3,
                types::PeerEvent::PeerInfoReceived {
                    network: *chain_config.magic_bytes(),
                    version: *chain_config.version(),
                    protocols: [
                        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                        Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                    ]
                    .into_iter()
                    .collect(),
                    subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                        .into_iter()
                        .collect(),
                }
            ))
        );
    }

    #[tokio::test]
    async fn handshake_outbound_tcp() {
        handshake_outbound::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn handshake_outbound_channels() {
        handshake_outbound::<TestTransportChannel, MockChannelTransport>().await;
    }

    #[tokio::test]
    async fn handshake_outbound_noise() {
        handshake_outbound::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn handshake_different_network<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(P2pConfig::default());
        let (tx1, _rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
            peer_id3,
            Role::Inbound,
            Arc::clone(&chain_config),
            p2p_config,
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move { peer.handshake().await });

        let mut socket2 = BufferedTranscoder::new(socket2);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                version: *chain_config.version(),
                network: [1, 2, 3, 4],
                protocols: [
                    Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                    Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                    Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                ]
                .into_iter()
                .collect(),
                subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                    .into_iter()
                    .collect(),
            }))
            .await
            .is_ok());

        assert_eq!(handle.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn handshake_different_network_tcp() {
        handshake_different_network::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn handshake_different_network_channels() {
        handshake_different_network::<TestTransportChannel, MockChannelTransport>().await;
    }

    #[tokio::test]
    async fn handshake_different_network_noise() {
        handshake_different_network::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn invalid_handshake_message<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(P2pConfig::default());
        let (tx1, _rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id2 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
            peer_id2,
            Role::Inbound,
            chain_config,
            p2p_config,
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move { peer.handshake().await });

        let mut socket2 = BufferedTranscoder::new(socket2);
        assert!(socket2.recv().now_or_never().is_none());
        socket2
            .send(types::Message::Request {
                request_id: types::MockRequestId::new(1337u64),
                request: message::Request::HeaderListRequest(message::HeaderListRequest::new(
                    Locator::new(vec![]),
                )),
            })
            .await
            .unwrap();

        assert_eq!(
            handle.await.unwrap(),
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );
    }

    #[tokio::test]
    async fn invalid_handshake_message_tcp() {
        invalid_handshake_message::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn invalid_handshake_message_channels() {
        invalid_handshake_message::<TestTransportChannel, MockChannelTransport>().await;
    }

    #[tokio::test]
    async fn invalid_handshake_message_noise() {
        invalid_handshake_message::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    pub async fn get_two_connected_sockets<A, T>() -> (T::Stream, T::Stream)
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let transport = A::make_transport();
        let addr = A::make_address();
        let mut server = transport.bind(addr).await.unwrap();
        let peer_fut = transport.connect(server.local_address().unwrap());

        let (res1, res2) = tokio::join!(server.accept(), peer_fut);
        (res1.unwrap().0, res2.unwrap())
    }
}

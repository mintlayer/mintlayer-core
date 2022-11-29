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
            transport::TransportSocket,
            types::{self, MockEvent, MockPeerId, PeerEvent},
        },
        types::{Protocol, ProtocolType},
    },
};

use super::transport::BufferedTranscoder;

pub enum Role {
    Inbound,
    Outbound,
}

pub struct Peer<T: TransportSocket> {
    /// Peer ID of the local node
    local_peer_id: MockPeerId,

    /// Peer ID of the remote node
    remote_peer_id: MockPeerId,

    /// Chain config
    config: Arc<ChainConfig>,

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
    pub fn new(
        local_peer_id: MockPeerId,
        remote_peer_id: MockPeerId,
        role: Role,
        config: Arc<ChainConfig>,
        socket: T::Stream,
        tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
        rx: mpsc::Receiver<MockEvent>,
    ) -> Self {
        let socket = BufferedTranscoder::new(socket);
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
                                Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                                Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                                Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
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
                            Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                            Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                            Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
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
                    MockEvent::SendMessage(message) => self.socket.send(*message).await?,
                },
                event = self.socket.recv() => match event {
                    Err(err) => {
                        log::info!("peer connection closed, reason {err:?}");
                        return self.destroy_peer().await;
                    }
                    Ok(None) => {},
                    Ok(Some(message)) => {
                        self.tx
                            .send((
                                self.remote_peer_id,
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
    use crate::{
        message,
        net::mock::{
            transport::{MockChannelTransport, TcpTransportSocket, TransportListener},
            types,
        },
    };
    use chainstate::Locator;
    use common::primitives::semver::SemVer;
    use futures::FutureExt;
    use p2p_test_utils::{MakeChannelAddress, MakeTcpAddress, MakeTestAddress};

    async fn handshake_inbound<A, T>()
    where
        A: MakeTestAddress<Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
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

        let mut socket2 = BufferedTranscoder::new(socket2);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                peer_id: peer_id2,
                version: *config.version(),
                network: *config.magic_bytes(),
                protocols: [
                    Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                    Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                    Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
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
                        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                        Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                    ]
                    .into_iter()
                    .collect(),
                }
            ))
        );
    }

    #[tokio::test]
    async fn handshake_inbound_tcp() {
        handshake_inbound::<MakeTcpAddress, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn handshake_inbound_channels() {
        handshake_inbound::<MakeChannelAddress, MockChannelTransport>().await;
    }

    async fn handshake_outbound<A, T>()
    where
        A: MakeTestAddress<Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, mut rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
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

        let mut socket2 = BufferedTranscoder::new(socket2);
        if let Some(_message) = socket2.recv().await.unwrap() {
            assert!(socket2
                .send(types::Message::Handshake(
                    types::HandshakeMessage::HelloAck {
                        peer_id: peer_id2,
                        version: *config.version(),
                        network: *config.magic_bytes(),
                        protocols: [
                            Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                            Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                            Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
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
                        Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                        Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                    ]
                    .into_iter()
                    .collect(),
                }
            ))
        );
    }

    #[tokio::test]
    async fn handshake_outbound_tcp() {
        handshake_outbound::<MakeTcpAddress, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn handshake_outbound_channels() {
        handshake_outbound::<MakeChannelAddress, MockChannelTransport>().await;
    }

    async fn handshake_different_network<A, T>()
    where
        A: MakeTestAddress<Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, _rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();
        let peer_id3 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
            peer_id1,
            peer_id3,
            Role::Inbound,
            Arc::clone(&config),
            socket1,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move { peer.handshake().await });

        let mut socket2 = BufferedTranscoder::new(socket2);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                peer_id: peer_id2,
                version: *config.version(),
                network: [1, 2, 3, 4],
                protocols: [
                    Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                    Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
                    Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
                ]
                .into_iter()
                .collect(),
            }))
            .await
            .is_ok());

        assert_eq!(handle.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn handshake_different_network_tcp() {
        handshake_different_network::<MakeTcpAddress, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn handshake_different_network_channels() {
        handshake_different_network::<MakeChannelAddress, MockChannelTransport>().await;
    }

    async fn invalid_handshake_message<A, T>()
    where
        A: MakeTestAddress<Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let config = Arc::new(common::chain::config::create_mainnet());
        let (tx1, _rx1) = mpsc::channel(16);
        let (_tx2, rx2) = mpsc::channel(16);
        let peer_id1 = MockPeerId::random();
        let peer_id2 = MockPeerId::random();

        let mut peer = Peer::<T>::new(
            peer_id1,
            peer_id2,
            Role::Inbound,
            Arc::clone(&config),
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
        invalid_handshake_message::<MakeTcpAddress, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn invalid_handshake_message_channels() {
        invalid_handshake_message::<MakeChannelAddress, MockChannelTransport>().await;
    }

    pub async fn get_two_connected_sockets<A, T>() -> (T::Stream, T::Stream)
    where
        A: MakeTestAddress<Address = T::Address>,
        T: TransportSocket,
    {
        let transport = T::new();
        let addr = A::make_address();
        let mut server = transport.bind(addr).await.unwrap();
        let peer_fut = transport.connect(server.local_address().unwrap());

        let (res1, res2) = tokio::join!(server.accept(), peer_fut);
        (res1.unwrap().0, res2.unwrap())
    }
}

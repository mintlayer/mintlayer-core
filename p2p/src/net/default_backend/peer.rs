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

use common::{chain::ChainConfig, primitives::user_agent::UserAgent};
use logging::log;
use utils::set_flag::SetFlag;

use crate::{
    config::P2pConfig,
    error::{P2pError, ProtocolError},
    net::{
        default_backend::{
            transport::TransportSocket,
            types::{self, Event, PeerEvent},
        },
        types::Role,
    },
    types::{peer_address::PeerAddress, peer_id::PeerId},
};

use super::{transport::BufferedTranscoder, types::HandshakeNonce};

const PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Inbound,
    Outbound { handshake_nonce: HandshakeNonce },
}

impl From<PeerRole> for Role {
    fn from(role: PeerRole) -> Self {
        match role {
            PeerRole::Inbound => Role::Inbound,
            PeerRole::Outbound { handshake_nonce: _ } => Role::Outbound,
        }
    }
}

pub struct Peer<T: TransportSocket> {
    /// Peer ID of the remote node
    peer_id: PeerId,

    /// Chain config
    chain_config: Arc<ChainConfig>,

    p2p_config: Arc<P2pConfig>,

    /// Is the connection inbound or outbound
    peer_role: PeerRole,

    /// Peer socket
    socket: BufferedTranscoder<T::Stream>,

    /// Socket address of the remote peer as seen by this node (addr_you in bitcoin)
    receiver_address: Option<PeerAddress>,

    /// TX channel for communicating with backend
    tx: mpsc::UnboundedSender<(PeerId, PeerEvent)>,

    /// RX channel for receiving commands from backend
    rx: mpsc::UnboundedReceiver<Event>,
}

impl<T> Peer<T>
where
    T: TransportSocket,
{
    #![allow(clippy::too_many_arguments)]
    pub fn new(
        peer_id: PeerId,
        peer_role: PeerRole,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        socket: T::Stream,
        receiver_address: Option<PeerAddress>,
        tx: mpsc::UnboundedSender<(PeerId, PeerEvent)>,
        rx: mpsc::UnboundedReceiver<Event>,
    ) -> Self {
        let socket = BufferedTranscoder::new(socket);

        Self {
            peer_id,
            peer_role,
            chain_config,
            p2p_config,
            socket,
            receiver_address,
            tx,
            rx,
        }
    }

    async fn handshake(&mut self) -> crate::Result<()> {
        match self.peer_role {
            PeerRole::Inbound => {
                let Ok(types::Message::Handshake(types::HandshakeMessage::Hello {
                    version,
                    network,
                    subscriptions,
                    receiver_address,
                    handshake_nonce,
                    user_agent,
                })) = self.socket.recv().await
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                };

                let user_agent = UserAgent::try_from(user_agent)
                    .map_err(|e| P2pError::ProtocolError(ProtocolError::InvalidUserAgent(e)))?;

                // Send PeerInfoReceived before sending handshake to remote peer!
                // Backend is expected to receive PeerInfoReceived before outgoing connection has chance to complete handshake,
                // It's required to reliable detect self-connects.
                self.tx
                    .send((
                        self.peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            network,
                            version,
                            subscriptions,
                            receiver_address,
                            handshake_nonce,
                            user_agent,
                        },
                    ))
                    .map_err(P2pError::from)?;

                self.socket
                    .send(types::Message::Handshake(
                        types::HandshakeMessage::HelloAck {
                            version: *self.chain_config.version(),
                            network: *self.chain_config.magic_bytes(),
                            user_agent: self.chain_config.user_agent().as_ref().to_owned(),
                            subscriptions: (*self.p2p_config.node_type.as_ref()).into(),
                            receiver_address: self.receiver_address.clone(),
                        },
                    ))
                    .await?;
            }
            PeerRole::Outbound { handshake_nonce } => {
                self.socket
                    .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                        version: *self.chain_config.version(),
                        network: *self.chain_config.magic_bytes(),
                        user_agent: self.chain_config.user_agent().as_ref().to_owned(),
                        subscriptions: (*self.p2p_config.node_type.as_ref()).into(),
                        receiver_address: self.receiver_address.clone(),
                        handshake_nonce,
                    }))
                    .await?;

                let Ok(types::Message::Handshake(types::HandshakeMessage::HelloAck {
                    version,
                    network,
                    user_agent,
                    subscriptions,
                    receiver_address,
                })) = self.socket.recv().await
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                };

                let user_agent = UserAgent::try_from(user_agent)
                    .map_err(|e| P2pError::ProtocolError(ProtocolError::InvalidUserAgent(e)))?;

                self.tx
                    .send((
                        self.peer_id,
                        types::PeerEvent::PeerInfoReceived {
                            network,
                            version,
                            user_agent,
                            subscriptions,
                            receiver_address,
                            handshake_nonce,
                        },
                    ))
                    .map_err(P2pError::from)?;
            }
        }

        Ok(())
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

        let mut was_accepted = SetFlag::default();

        loop {
            tokio::select! {
                // Sending messages should have higher priority
                biased;

                event = self.rx.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    Event::Accepted => was_accepted.set(),
                    Event::SendMessage(message) => self.socket.send(*message).await?,
                },
                event = self.socket.recv(), if *was_accepted => match event {
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
                            ))?;
                    }
                }
            }
        }
    }
}

impl<T: TransportSocket> Drop for Peer<T> {
    fn drop(&mut self) {
        let _ = self.tx.send((self.peer_id, types::PeerEvent::ConnectionClosed));
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
            default_backend::{
                transport::{
                    MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket, TransportListener,
                },
                types,
            },
            types::PubSubTopic,
        },
    };
    use chainstate::Locator;
    use futures::FutureExt;

    async fn handshake_inbound<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(P2pConfig::default());
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id2 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id2,
            PeerRole::Inbound,
            Arc::clone(&chain_config),
            p2p_config,
            socket1,
            None,
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
                user_agent: chain_config.user_agent().as_ref().to_owned(),
                subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                    .into_iter()
                    .collect(),
                receiver_address: None,
                handshake_nonce: 123,
            }))
            .await
            .is_ok());

        let _peer = handle.await.unwrap();
        assert_eq!(
            rx1.try_recv().unwrap().1,
            types::PeerEvent::PeerInfoReceived {
                network: *chain_config.magic_bytes(),
                version: *chain_config.version(),
                user_agent: chain_config.user_agent().clone(),
                subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                    .into_iter()
                    .collect(),
                receiver_address: None,
                handshake_nonce: 123,
            }
        );
    }

    #[tokio::test]
    async fn handshake_inbound_tcp() {
        handshake_inbound::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn handshake_inbound_channels() {
        handshake_inbound::<TestTransportChannel, MpscChannelTransport>().await;
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
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id3 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id3,
            PeerRole::Outbound { handshake_nonce: 1 },
            Arc::clone(&chain_config),
            p2p_config,
            socket1,
            None,
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
                    user_agent: chain_config.user_agent().as_ref().to_owned(),
                    subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                        .into_iter()
                        .collect(),
                    receiver_address: None,
                }
            ))
            .await
            .is_ok());

        let _peer = handle.await.unwrap();
        assert_eq!(
            rx1.try_recv(),
            Ok((
                peer_id3,
                PeerEvent::PeerInfoReceived {
                    network: *chain_config.magic_bytes(),
                    version: *chain_config.version(),
                    user_agent: chain_config.user_agent().clone(),
                    subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                        .into_iter()
                        .collect(),
                    receiver_address: None,
                    handshake_nonce: 1,
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
        handshake_outbound::<TestTransportChannel, MpscChannelTransport>().await;
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
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id3 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id3,
            PeerRole::Inbound,
            Arc::clone(&chain_config),
            p2p_config,
            socket1,
            None,
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
                user_agent: chain_config.user_agent().as_ref().to_owned(),
                subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                    .into_iter()
                    .collect(),
                receiver_address: None,
                handshake_nonce: 123,
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
        handshake_different_network::<TestTransportChannel, MpscChannelTransport>().await;
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
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id2 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id2,
            PeerRole::Inbound,
            chain_config,
            p2p_config,
            socket1,
            None,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move { peer.handshake().await });

        let mut socket2 = BufferedTranscoder::new(socket2);
        assert!(socket2.recv().now_or_never().is_none());
        socket2
            .send(types::Message::HeaderListRequest(
                message::HeaderListRequest::new(Locator::new(vec![])),
            ))
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
        invalid_handshake_message::<TestTransportChannel, MpscChannelTransport>().await;
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
        let mut server = transport.bind(vec![addr]).await.unwrap();
        let peer_fut = transport.connect(server.local_addresses().unwrap()[0].clone());

        let (res1, res2) = tokio::join!(server.accept(), peer_fut);
        (res1.unwrap().0, res2.unwrap())
    }
}

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

use tokio::{
    sync::mpsc::{self, Sender},
    time::timeout,
};

use common::chain::ChainConfig;
use logging::log;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    message::{PeerManagerMessage, SyncMessage},
    net::{
        default_backend::{
            transport::TransportSocket,
            types::{self, Event, PeerEvent},
        },
        types::Role,
    },
    protocol::NETWORK_PROTOCOL_CURRENT,
    types::{peer_address::PeerAddress, peer_id::PeerId},
};

use super::{
    transport::BufferedTranscoder,
    types::{HandshakeNonce, Message, P2pTimestamp},
};

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
        let socket = BufferedTranscoder::new(socket, *p2p_config.max_message_size);

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

    fn validate_peer_time(
        p2p_config: &P2pConfig,
        local_time: Duration,
        remote_time: Duration,
    ) -> crate::Result<()> {
        // TODO: If the node's clock is wrong and we disconnect peers,
        // it can be trivial to isolate the node by connecting malicious nodes
        // with the same invalid clock (while honest nodes can't connect).
        // After that, the node is open to all kinds of attacks.
        let time_diff =
            std::cmp::max(local_time, remote_time) - std::cmp::min(local_time, remote_time);
        utils::ensure!(
            time_diff <= *p2p_config.max_clock_diff,
            P2pError::PeerError(PeerError::TimeDiff(time_diff))
        );
        Ok(())
    }

    async fn handshake(&mut self, local_time: P2pTimestamp) -> crate::Result<()> {
        match self.peer_role {
            PeerRole::Inbound => {
                let types::Message::Handshake(types::HandshakeMessage::Hello {
                    protocol,
                    network,
                    services,
                    user_agent,
                    version,
                    receiver_address,
                    current_time: remote_time,
                    handshake_nonce,
                }) = self.socket.recv().await?
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected));
                };

                Self::validate_peer_time(
                    &self.p2p_config,
                    local_time.as_duration_since_epoch(),
                    remote_time.as_duration_since_epoch(),
                )?;

                // Send PeerInfoReceived before sending handshake to remote peer!
                // Backend is expected to receive PeerInfoReceived before outgoing connection has chance to complete handshake,
                // It's required to reliable detect self-connects.
                self.tx.send((
                    self.peer_id,
                    PeerEvent::PeerInfoReceived {
                        protocol,
                        network,
                        services,
                        user_agent,
                        version,
                        receiver_address,
                        handshake_nonce,
                    },
                ))?;

                self.socket
                    .send(types::Message::Handshake(
                        types::HandshakeMessage::HelloAck {
                            protocol: NETWORK_PROTOCOL_CURRENT,
                            network: *self.chain_config.magic_bytes(),
                            user_agent: self.p2p_config.user_agent.clone(),
                            version: *self.chain_config.version(),
                            services: (*self.p2p_config.node_type).into(),
                            receiver_address: self.receiver_address.clone(),
                            current_time: local_time,
                        },
                    ))
                    .await?;
            }
            PeerRole::Outbound { handshake_nonce } => {
                self.socket
                    .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                        protocol: NETWORK_PROTOCOL_CURRENT,
                        network: *self.chain_config.magic_bytes(),
                        services: (*self.p2p_config.node_type).into(),
                        user_agent: self.p2p_config.user_agent.clone(),
                        version: *self.chain_config.version(),
                        receiver_address: self.receiver_address.clone(),
                        current_time: local_time,
                        handshake_nonce,
                    }))
                    .await?;

                let types::Message::Handshake(types::HandshakeMessage::HelloAck {
                    protocol,
                    network,
                    user_agent,
                    version,
                    services,
                    receiver_address,
                    current_time: remote_time,
                }) = self.socket.recv().await?
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected));
                };

                Self::validate_peer_time(
                    &self.p2p_config,
                    local_time.as_duration_since_epoch(),
                    remote_time.as_duration_since_epoch(),
                )?;

                self.tx.send((
                    self.peer_id,
                    PeerEvent::PeerInfoReceived {
                        protocol,
                        network,
                        services,
                        user_agent,
                        version,
                        receiver_address,
                        handshake_nonce,
                    },
                ))?;
            }
        }

        Ok(())
    }

    async fn handle_socket_msg(
        peer: PeerId,
        msg: Message,
        tx: &mut mpsc::UnboundedSender<(PeerId, PeerEvent)>,
        sync_tx: &mut Sender<SyncMessage>,
    ) -> crate::Result<()> {
        // TODO: Use a bounded channel to send messages to the peer manager
        match msg {
            Message::Handshake(_) => {
                log::error!("peer {peer} sent handshaking message");
            }

            Message::PingRequest(r) => tx.send((
                peer,
                PeerEvent::MessageReceived {
                    message: PeerManagerMessage::PingRequest(r),
                },
            ))?,
            Message::PingResponse(r) => tx.send((
                peer,
                PeerEvent::MessageReceived {
                    message: PeerManagerMessage::PingResponse(r),
                },
            ))?,
            Message::AddrListRequest(r) => tx.send((
                peer,
                PeerEvent::MessageReceived {
                    message: PeerManagerMessage::AddrListRequest(r),
                },
            ))?,
            Message::AddrListResponse(r) => tx.send((
                peer,
                PeerEvent::MessageReceived {
                    message: PeerManagerMessage::AddrListResponse(r),
                },
            ))?,
            Message::AnnounceAddrRequest(r) => tx.send((
                peer,
                PeerEvent::MessageReceived {
                    message: PeerManagerMessage::AnnounceAddrRequest(r),
                },
            ))?,

            Message::HeaderListRequest(v) => {
                sync_tx.send(SyncMessage::HeaderListRequest(v)).await?
            }
            Message::BlockListRequest(v) => sync_tx.send(SyncMessage::BlockListRequest(v)).await?,
            Message::TransactionRequest(v) => {
                sync_tx.send(SyncMessage::TransactionRequest(v)).await?
            }
            Message::NewTransaction(v) => sync_tx.send(SyncMessage::NewTransaction(v)).await?,
            Message::TransactionResponse(v) => {
                sync_tx.send(SyncMessage::TransactionResponse(v)).await?
            }
            Message::HeaderList(v) => sync_tx.send(SyncMessage::HeaderList(v)).await?,
            Message::BlockResponse(v) => sync_tx.send(SyncMessage::BlockResponse(v)).await?,
        }

        Ok(())
    }

    pub async fn run(mut self, local_time: P2pTimestamp) -> crate::Result<()> {
        // handshake with remote peer and send peer's info to backend
        let handshake_res = timeout(PEER_HANDSHAKE_TIMEOUT, self.handshake(local_time)).await;
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

        // The channel to the sync manager peer task (set when the peer is accepted)
        let mut sync_tx_opt = None;

        loop {
            tokio::select! {
                // Sending messages should have higher priority
                biased;

                event = self.rx.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    Event::Accepted{ sync_tx } => {
                        sync_tx_opt = Some(sync_tx);
                    },
                    Event::SendMessage(message) => self.socket.send(*message).await?,
                },
                event = self.socket.recv(), if sync_tx_opt.is_some() => match event {
                    Ok(message) => {
                        Self::handle_socket_msg(self.peer_id, message, &mut self.tx, sync_tx_opt.as_mut().expect("sync_tx_opt is some")).await?;
                    }
                    Err(err) => {
                        log::info!("peer connection closed, reason {err:?}");
                        return Ok(());
                    }
                }
            }
        }
    }
}

impl<T: TransportSocket> Drop for Peer<T> {
    fn drop(&mut self) {
        let _ = self.tx.send((self.peer_id, PeerEvent::ConnectionClosed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::types::services::Service;
    use crate::testing_utils::{
        test_p2p_config, TestTransportChannel, TestTransportMaker, TestTransportNoise,
        TestTransportTcp,
    };
    use crate::{
        message,
        net::default_backend::{
            transport::{
                MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket, TransportListener,
            },
            types,
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
        let p2p_config = Arc::new(test_p2p_config());
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id2 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id2,
            PeerRole::Inbound,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            socket1,
            None,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move {
            peer.handshake(P2pTimestamp::from_int_seconds(123456)).await.unwrap();
            peer
        });

        let mut socket2 = BufferedTranscoder::new(socket2, *p2p_config.max_message_size);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                protocol: NETWORK_PROTOCOL_CURRENT,
                version: *chain_config.version(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_int_seconds(123456),
                handshake_nonce: 123,
            }))
            .await
            .is_ok());

        let _peer = handle.await.unwrap();
        assert_eq!(
            rx1.try_recv().unwrap().1,
            PeerEvent::PeerInfoReceived {
                protocol: NETWORK_PROTOCOL_CURRENT,
                network: *chain_config.magic_bytes(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
                user_agent: p2p_config.user_agent.clone(),
                version: *chain_config.version(),
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
        let p2p_config = Arc::new(test_p2p_config());
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id3 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id3,
            PeerRole::Outbound { handshake_nonce: 1 },
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            socket1,
            None,
            tx1,
            rx2,
        );

        let handle = tokio::spawn(async move {
            peer.handshake(P2pTimestamp::from_int_seconds(123456)).await.unwrap();
            peer
        });

        let mut socket2 = BufferedTranscoder::new(socket2, *p2p_config.max_message_size);
        socket2.recv().await.unwrap();
        assert!(socket2
            .send(types::Message::Handshake(
                types::HandshakeMessage::HelloAck {
                    protocol: NETWORK_PROTOCOL_CURRENT,
                    version: *chain_config.version(),
                    network: *chain_config.magic_bytes(),
                    user_agent: p2p_config.user_agent.clone(),
                    services: [Service::Blocks, Service::Transactions].as_slice().into(),
                    receiver_address: None,
                    current_time: P2pTimestamp::from_int_seconds(123456),
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
                    protocol: NETWORK_PROTOCOL_CURRENT,
                    network: *chain_config.magic_bytes(),
                    services: [Service::Blocks, Service::Transactions].as_slice().into(),
                    user_agent: p2p_config.user_agent.clone(),
                    version: *chain_config.version(),
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
        let p2p_config = Arc::new(test_p2p_config());
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id3 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id3,
            PeerRole::Inbound,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            socket1,
            None,
            tx1,
            rx2,
        );

        let local_time = P2pTimestamp::from_int_seconds(123456);
        let handle = tokio::spawn(async move { peer.handshake(local_time).await });

        let mut socket2 = BufferedTranscoder::new(socket2, *p2p_config.max_message_size);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(types::Message::Handshake(types::HandshakeMessage::Hello {
                protocol: NETWORK_PROTOCOL_CURRENT,
                version: *chain_config.version(),
                network: [1, 2, 3, 4],
                user_agent: p2p_config.user_agent.clone(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
                receiver_address: None,
                current_time: local_time,
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
        let p2p_config = Arc::new(test_p2p_config());
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id2 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id2,
            PeerRole::Inbound,
            chain_config,
            Arc::clone(&p2p_config),
            socket1,
            None,
            tx1,
            rx2,
        );

        let local_time = P2pTimestamp::from_int_seconds(123456);
        let handle = tokio::spawn(async move { peer.handshake(local_time).await });

        let mut socket2 = BufferedTranscoder::new(socket2, *p2p_config.max_message_size);
        assert!(socket2.recv().now_or_never().is_none());
        socket2
            .send(types::Message::HeaderListRequest(
                message::HeaderListRequest::new(Locator::new(vec![])),
            ))
            .await
            .unwrap();

        assert!(matches!(
            handle.await.unwrap(),
            Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected))
        ),);
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

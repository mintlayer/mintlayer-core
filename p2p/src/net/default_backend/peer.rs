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

use p2p_types::services::Services;
use tokio::{sync::mpsc, time::timeout};

use common::{chain::ChainConfig, primitives::time::Time, time_getter::TimeGetter};
use logging::log;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    message::{BlockSyncMessage, TransactionSyncMessage},
    net::{
        default_backend::{
            transport::TransportSocket,
            types::{BackendEvent, PeerEvent},
        },
        types::Role,
    },
    protocol::{choose_common_protocol_version, ProtocolVersion},
    types::{peer_address::PeerAddress, peer_id::PeerId},
};

use super::{
    transport::BufferedTranscoder,
    types::{CategorizedMessage, HandshakeMessage, HandshakeNonce, Message, P2pTimestamp},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionInfo {
    Inbound,
    Outbound {
        handshake_nonce: HandshakeNonce,
        local_services_override: Option<Services>,
    },
}

impl From<ConnectionInfo> for Role {
    fn from(role: ConnectionInfo) -> Self {
        match role {
            ConnectionInfo::Inbound => Role::Inbound,
            ConnectionInfo::Outbound {
                handshake_nonce: _,
                local_services_override: _,
            } => Role::Outbound,
        }
    }
}

pub struct Peer<T: TransportSocket> {
    /// Peer ID of the remote node
    peer_id: PeerId,

    /// Chain config
    chain_config: Arc<ChainConfig>,

    p2p_config: Arc<P2pConfig>,

    connection_info: ConnectionInfo,

    /// Peer socket
    socket: BufferedTranscoder<T::Stream>,

    /// Socket address of the remote peer as seen by this node (addr_you in bitcoin)
    receiver_address: Option<PeerAddress>,

    /// Channel sender for sending events to Backend
    peer_event_sender: mpsc::Sender<PeerEvent>,

    /// Channel receiver for receiving events from Backend.
    backend_event_receiver: mpsc::UnboundedReceiver<BackendEvent>,

    /// The protocol version that this node is running. Normally this will be
    /// equal to default_networking_service::PREFERRED_PROTOCOL_VERSION, but it can be
    /// overridden for testing purposes.
    node_protocol_version: ProtocolVersion,

    /// Time getter
    time_getter: TimeGetter,
}

impl<T> Peer<T>
where
    T: TransportSocket,
{
    #![allow(clippy::too_many_arguments)]
    pub fn new(
        peer_id: PeerId,
        connection_info: ConnectionInfo,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        socket: T::Stream,
        receiver_address: Option<PeerAddress>,
        peer_event_sender: mpsc::Sender<PeerEvent>,
        backend_event_receiver: mpsc::UnboundedReceiver<BackendEvent>,
        node_protocol_version: ProtocolVersion,
        time_getter: TimeGetter,
    ) -> Self {
        let socket = BufferedTranscoder::new(socket, *p2p_config.protocol_config.max_message_size);

        Self {
            peer_id,
            connection_info,
            chain_config,
            p2p_config,
            socket,
            receiver_address,
            peer_event_sender,
            backend_event_receiver,
            node_protocol_version,
            time_getter,
        }
    }

    fn validate_peer_time(
        p2p_config: &P2pConfig,
        local_time_start: Time,
        local_time_end: Time,
        remote_time: P2pTimestamp,
    ) -> crate::Result<()> {
        // TODO: If the node's clock is wrong and we disconnect peers,
        // it can be trivial to isolate the node by connecting malicious nodes
        // with the same invalid clock (while honest nodes can't connect).
        // After that, the node is open to all kinds of attacks.

        // We do not know at what point exactly the peer recorded its timestamp. However, we do
        // know it was somewhere between the request was initiated and the response was received.
        // We give the peer some leeway when it comes to network latency so the acceptable time is
        // in the interval [`init_time - tolerance`, `recv_time + tolerance`].
        //
        // Since the distance between `init_time` and `recv_time` is bounded by the handshake
        // timeout, the effective max clock diff between a node and any of its peers is:
        // ```tolerance + (recv_time - init_time) <= tolerance + handshake_timeout```
        //
        // The effective tolerance of clock diff between any two peers the node is connected to is
        // given by the span of the acceptable time interval: `handshake_timeout + 2 * tolerance`.

        let max_offset = *p2p_config.max_clock_diff;
        let accepted_peer_time_start = (local_time_start - max_offset)
            .expect("Local clock minus a small offset should not underflow");
        let accepted_peer_time_end = (local_time_end + max_offset)
            .expect("Local time plus a small offset should not overflow");
        let accepted_peer_time = accepted_peer_time_start..=accepted_peer_time_end;

        let remote_time = Time::from_duration_since_epoch(remote_time.as_duration_since_epoch());

        utils::ensure!(
            accepted_peer_time.contains(&remote_time),
            P2pError::PeerError(PeerError::TimeDiff(remote_time, accepted_peer_time)),
        );

        Ok(())
    }

    async fn handshake(&mut self) -> crate::Result<()> {
        let init_time = self.time_getter.get_time();
        match self.connection_info {
            ConnectionInfo::Inbound => {
                let Message::Handshake(HandshakeMessage::Hello {
                    protocol_version,
                    network,
                    services: remote_services,
                    user_agent,
                    software_version,
                    receiver_address,
                    current_time: remote_time,
                    handshake_nonce,
                }) = self.socket.recv().await?
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected));
                };

                let recv_time = self.time_getter.get_time();
                Self::validate_peer_time(&self.p2p_config, init_time, recv_time, remote_time)?;

                let local_services: Services = (*self.p2p_config.node_type).into();

                let common_services = local_services & remote_services;

                let common_protocol_version =
                    choose_common_protocol_version(protocol_version, self.node_protocol_version)?;

                // Send PeerInfoReceived before sending handshake to remote peer!
                // Backend is expected to receive PeerInfoReceived before outgoing connection has chance to complete handshake,
                // It's required to reliably detect self-connects.
                self.peer_event_sender
                    .send(PeerEvent::PeerInfoReceived {
                        protocol_version: common_protocol_version,
                        network,
                        common_services,
                        user_agent,
                        software_version,
                        receiver_address,
                        handshake_nonce,
                    })
                    .await?;

                self.socket
                    .send(Message::Handshake(HandshakeMessage::HelloAck {
                        protocol_version: self.node_protocol_version,
                        network: *self.chain_config.magic_bytes(),
                        user_agent: self.p2p_config.user_agent.clone(),
                        software_version: *self.chain_config.software_version(),
                        services: (*self.p2p_config.node_type).into(),
                        receiver_address: self.receiver_address.clone(),
                        current_time: P2pTimestamp::from_time(self.time_getter.get_time()),
                    }))
                    .await?;
            }
            ConnectionInfo::Outbound {
                handshake_nonce,
                local_services_override,
            } => {
                let local_services =
                    local_services_override.unwrap_or_else(|| (*self.p2p_config.node_type).into());

                self.socket
                    .send(Message::Handshake(HandshakeMessage::Hello {
                        protocol_version: self.node_protocol_version,
                        network: *self.chain_config.magic_bytes(),
                        services: local_services,
                        user_agent: self.p2p_config.user_agent.clone(),
                        software_version: *self.chain_config.software_version(),
                        receiver_address: self.receiver_address.clone(),
                        current_time: P2pTimestamp::from_time(init_time),
                        handshake_nonce,
                    }))
                    .await?;

                let Message::Handshake(HandshakeMessage::HelloAck {
                    protocol_version,
                    network,
                    user_agent,
                    software_version,
                    services: remote_services,
                    receiver_address,
                    current_time: remote_time,
                }) = self.socket.recv().await?
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected));
                };

                let recv_time = self.time_getter.get_time();
                Self::validate_peer_time(&self.p2p_config, init_time, recv_time, remote_time)?;

                let common_services = local_services & remote_services;

                let common_protocol_version =
                    choose_common_protocol_version(protocol_version, self.node_protocol_version)?;

                self.peer_event_sender
                    .send(PeerEvent::PeerInfoReceived {
                        protocol_version: common_protocol_version,
                        network,
                        common_services,
                        user_agent,
                        software_version,
                        receiver_address,
                        handshake_nonce,
                    })
                    .await?;
            }
        }

        Ok(())
    }

    // Note: the channels used by this function to propagate messages to other parts of p2p
    // must be bounded; this is important to prevent DoS attacks.
    async fn handle_socket_msg(
        peer_id: PeerId,
        msg: Message,
        peer_event_sender: &mut mpsc::Sender<PeerEvent>,
        block_sync_msg_sender: &mut mpsc::Sender<BlockSyncMessage>,
        transaction_sync_msg_sender: &mut mpsc::Sender<TransactionSyncMessage>,
    ) -> crate::Result<()> {
        match msg.categorize() {
            CategorizedMessage::Handshake(_) => {
                log::error!("Peer {peer_id} sent unexpected handshake message");

                peer_event_sender
                    .send(PeerEvent::Misbehaved {
                        error: P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                            "Unexpected handshake message".to_owned(),
                        )),
                    })
                    .await?;
            }
            CategorizedMessage::PeerManagerMessage(msg) => {
                peer_event_sender.send(PeerEvent::MessageReceived { message: msg }).await?
            }
            CategorizedMessage::BlockSyncMessage(msg) => block_sync_msg_sender.send(msg).await?,
            CategorizedMessage::TransactionSyncMessage(msg) => {
                transaction_sync_msg_sender.send(msg).await?
            }
        }

        Ok(())
    }

    async fn run_handshake(&mut self) -> crate::Result<()> {
        // handshake with remote peer and send peer's info to backend
        let handshake_timeout = *self.p2p_config.peer_handshake_timeout;
        let handshake_res = timeout(handshake_timeout, self.handshake()).await;

        match handshake_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                log::debug!("handshake failed for peer {}: {err}", self.peer_id);

                let send_result = self
                    .peer_event_sender
                    .send(PeerEvent::HandshakeFailed { error: err.clone() })
                    .await;
                if let Err(send_error) = send_result {
                    log::error!(
                        "Cannot send PeerEvent::HandshakeFailed to peer {}: {}",
                        self.peer_id,
                        send_error
                    );
                }

                return Err(err);
            }
            Err(_) => {
                log::debug!("handshake timeout for peer {}", self.peer_id);
                return Err(P2pError::ProtocolError(ProtocolError::Unresponsive));
            }
        }

        Ok(())
    }

    async fn run_impl(&mut self) -> crate::Result<()> {
        // Run the handshake sequence first
        self.run_handshake().await?;

        // The channel to the sync manager peer task (set when the peer is accepted)
        let mut sync_msg_senders_opt = None;

        loop {
            tokio::select! {
                // Sending messages should have higher priority
                biased;

                event = self.backend_event_receiver.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    BackendEvent::Accepted{ block_sync_msg_sender, transaction_sync_msg_sender } => {
                        sync_msg_senders_opt = Some((block_sync_msg_sender, transaction_sync_msg_sender));
                    },
                    BackendEvent::SendMessage(message) => self.socket.send(*message).await?,
                },
                event = self.socket.recv(), if sync_msg_senders_opt.is_some() => match event {
                    Ok(message) => {
                        let sync_msg_senders = sync_msg_senders_opt.as_mut().expect("sync_msg_senders_opt is some");
                        Self::handle_socket_msg(
                            self.peer_id,
                            message,
                            &mut self.peer_event_sender,
                            &mut sync_msg_senders.0,
                            &mut sync_msg_senders.1,
                        ).await?;
                    }
                    Err(err) => {
                        log::info!("Connection closed for peer {}, reason {err:?}", self.peer_id);
                        return Ok(());
                    }
                }
            }
        }
    }

    pub async fn run(mut self) -> crate::Result<()> {
        let run_result = self.run_impl().await;
        let send_result = self.peer_event_sender.send(PeerEvent::ConnectionClosed).await;

        if let Err(send_error) = send_result {
            // Note: this situation is likely to happen if the connection is already closed,
            // so it's not really an error.
            log::debug!(
                "Unable to send PeerEvent::ConnectionClosed to Backend for peer {}: {}",
                self.peer_id,
                send_error
            );
        }

        run_result
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use std::time::Duration;
    use test_utils::mock_time_getter::{
        mocked_time_getter_milliseconds, mocked_time_getter_seconds,
    };
    use utils::atomics::SeqCstAtomicU64;

    use super::*;
    use crate::{
        message::HeaderListRequest,
        net::{
            default_backend::transport::{
                MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket,
            },
            types::services::Service,
        },
        testing_utils::{
            get_two_connected_sockets, test_p2p_config, TestTransportChannel, TestTransportMaker,
            TestTransportNoise, TestTransportTcp, TEST_PROTOCOL_VERSION,
        },
    };
    use chainstate::Locator;

    const TEST_CHAN_BUF_SIZE: usize = 100;

    async fn handshake_inbound<A, T>()
    where
        A: TestTransportMaker<Transport = T>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(test_p2p_config());
        let (peer_event_sender, mut peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
        let (_backend_event_sender, backend_event_receiver) = mpsc::unbounded_channel();
        let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
        let time_getter = mocked_time_getter_seconds(cur_time);
        let peer_id2 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id2,
            ConnectionInfo::Inbound,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            socket1,
            None,
            peer_event_sender,
            backend_event_receiver,
            TEST_PROTOCOL_VERSION.into(),
            time_getter,
        );

        let handle = logging::spawn_in_current_span(async move {
            peer.handshake().await.unwrap();
            peer
        });

        let mut socket2 =
            BufferedTranscoder::new(socket2, *p2p_config.protocol_config.max_message_size);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                software_version: *chain_config.software_version(),
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
            peer_event_receiver.try_recv().unwrap(),
            PeerEvent::PeerInfoReceived {
                protocol_version: TEST_PROTOCOL_VERSION,
                network: *chain_config.magic_bytes(),
                common_services: [Service::Blocks, Service::Transactions].as_slice().into(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: *chain_config.software_version(),
                receiver_address: None,
                handshake_nonce: 123,
            }
        );
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_inbound_tcp() {
        handshake_inbound::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_inbound_channels() {
        handshake_inbound::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_inbound_noise() {
        handshake_inbound::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn handshake_outbound<A, T>()
    where
        A: TestTransportMaker<Transport = T>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(test_p2p_config());
        let (peer_event_sender, mut peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
        let (_backend_event_sender, backend_event_receiver) = mpsc::unbounded_channel();
        let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
        let time_getter = mocked_time_getter_seconds(cur_time);
        let peer_id3 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id3,
            ConnectionInfo::Outbound {
                handshake_nonce: 1,
                local_services_override: None,
            },
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            socket1,
            None,
            peer_event_sender,
            backend_event_receiver,
            TEST_PROTOCOL_VERSION.into(),
            time_getter,
        );

        let handle = logging::spawn_in_current_span(async move {
            peer.handshake().await.unwrap();
            peer
        });

        let mut socket2 =
            BufferedTranscoder::new(socket2, *p2p_config.protocol_config.max_message_size);
        socket2.recv().await.unwrap();
        assert!(socket2
            .send(Message::Handshake(HandshakeMessage::HelloAck {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                software_version: *chain_config.software_version(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_int_seconds(123456),
            }))
            .await
            .is_ok());

        let _peer = handle.await.unwrap();
        assert_eq!(
            peer_event_receiver.try_recv(),
            Ok(PeerEvent::PeerInfoReceived {
                protocol_version: TEST_PROTOCOL_VERSION,
                network: *chain_config.magic_bytes(),
                common_services: [Service::Blocks, Service::Transactions].as_slice().into(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: *chain_config.software_version(),
                receiver_address: None,
                handshake_nonce: 1,
            })
        );
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_outbound_tcp() {
        handshake_outbound::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_outbound_channels() {
        handshake_outbound::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_outbound_noise() {
        handshake_outbound::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn handshake_different_network<A, T>()
    where
        A: TestTransportMaker<Transport = T>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(test_p2p_config());
        let (peer_event_sender, _peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
        let (_backend_event_sender, backend_event_receiver) = mpsc::unbounded_channel();
        let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&cur_time));
        let peer_id3 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id3,
            ConnectionInfo::Inbound,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            socket1,
            None,
            peer_event_sender,
            backend_event_receiver,
            TEST_PROTOCOL_VERSION.into(),
            time_getter,
        );

        let handle = logging::spawn_in_current_span(async move { peer.handshake().await });

        let mut socket2 =
            BufferedTranscoder::new(socket2, *p2p_config.protocol_config.max_message_size);
        assert!(socket2.recv().now_or_never().is_none());
        assert!(socket2
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                software_version: *chain_config.software_version(),
                network: [1, 2, 3, 4],
                user_agent: p2p_config.user_agent.clone(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_int_seconds(cur_time.load()),
                handshake_nonce: 123,
            }))
            .await
            .is_ok());

        assert_eq!(handle.await.unwrap(), Ok(()));
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_different_network_tcp() {
        handshake_different_network::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_different_network_channels() {
        handshake_different_network::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn handshake_different_network_noise() {
        handshake_different_network::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn invalid_handshake_message<A, T>()
    where
        A: TestTransportMaker<Transport = T>,
        T: TransportSocket,
    {
        let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(test_p2p_config());
        let (peer_event_sender, _peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
        let (_backend_event_sender, backend_event_receiver) = mpsc::unbounded_channel();
        let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
        let time_getter = mocked_time_getter_seconds(cur_time);
        let peer_id2 = PeerId::new();

        let mut peer = Peer::<T>::new(
            peer_id2,
            ConnectionInfo::Inbound,
            chain_config,
            Arc::clone(&p2p_config),
            socket1,
            None,
            peer_event_sender,
            backend_event_receiver,
            TEST_PROTOCOL_VERSION.into(),
            time_getter,
        );

        let handle = logging::spawn_in_current_span(async move { peer.handshake().await });

        let mut socket2 =
            BufferedTranscoder::new(socket2, *p2p_config.protocol_config.max_message_size);
        assert!(socket2.recv().now_or_never().is_none());
        socket2
            .send(Message::HeaderListRequest(HeaderListRequest::new(
                Locator::new(vec![]),
            )))
            .await
            .unwrap();

        assert!(matches!(
            handle.await.unwrap(),
            Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected))
        ),);
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn invalid_handshake_message_tcp() {
        invalid_handshake_message::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn invalid_handshake_message_channels() {
        invalid_handshake_message::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tracing::instrument]
    #[tokio::test]
    async fn invalid_handshake_message_noise() {
        invalid_handshake_message::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    #[rstest::rstest]
    #[case::all_in_sync(
        123456,
        123456,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
    #[case::peer_ahead_within_tolerance(
        100000,
        100009,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
    #[case::peer_ahead_within_tolerance_and_delay(
        100000,
        100011,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
    #[case::peer_ahead_too_much(
        100000,
        100014,
        Duration::from_secs(2),
        |res| assert!(matches!(res, Err(P2pError::PeerError(PeerError::TimeDiff(_, _))))),
    )]
    #[case::peer_behind_within_tolerance(
        100009,
        100000,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
    #[case::peer_behind_too_much(
        100014,
        100000,
        Duration::from_secs(2),
        |res| assert!(matches!(res, Err(P2pError::PeerError(PeerError::TimeDiff(_, _))))),
    )]
    #[case::peer_in_sync_but_times_out(
        100000,
        100000,
        Duration::from_secs(11),
        |res| assert_eq!(res, Err(P2pError::ProtocolError(ProtocolError::Unresponsive))),
    )]
    #[tokio::test]
    async fn handshake_timestamp_verification(
        #[case] local_init_time: u64,
        #[case] peer_init_time: u64,
        #[case] response_delay: Duration,
        #[case] result_check: impl FnOnce(crate::Result<()>),
    ) {
        tokio::time::pause();
        let local_time = Arc::new(SeqCstAtomicU64::new(1000 * local_init_time));
        let local_time_getter = mocked_time_getter_milliseconds(Arc::clone(&local_time));
        let peer_time = Arc::new(SeqCstAtomicU64::new(1000 * peer_init_time));
        let peer_time_getter = mocked_time_getter_milliseconds(Arc::clone(&peer_time));

        let (socket1, socket2) =
            get_two_connected_sockets::<TestTransportChannel, MpscChannelTransport>().await;
        let chain_config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config = Arc::new(test_p2p_config());
        let (tx1, _rx1) = mpsc::channel(TEST_CHAN_BUF_SIZE);
        let (_tx2, rx2) = mpsc::unbounded_channel();
        let peer_id3 = PeerId::new();

        let mut peer = Peer::<MpscChannelTransport>::new(
            peer_id3,
            ConnectionInfo::Outbound {
                handshake_nonce: 1,
                local_services_override: None,
            },
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            socket1,
            None,
            tx1,
            rx2,
            TEST_PROTOCOL_VERSION.into(),
            peer_time_getter,
        );

        let handle = logging::spawn_in_current_span(async move { peer.run_handshake().await });

        // Advance both peer clocks and tokio time by given delay in 200ms increments to simulate
        // the flow of time. Doing this in one step makes the test result sensitive to the runtime
        // scheduler behavior.
        let increment = 200;
        for _ in 0..(response_delay.as_millis() as u64 / increment) {
            local_time.fetch_add(increment);
            peer_time.fetch_add(increment);
            tokio::time::advance(Duration::from_millis(increment)).await;
        }

        let mut socket2 =
            BufferedTranscoder::new(socket2, *p2p_config.protocol_config.max_message_size);
        socket2.recv().await.unwrap();
        let _ = socket2
            .send(Message::Handshake(HandshakeMessage::HelloAck {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                software_version: *chain_config.software_version(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_time(local_time_getter.get_time()),
            }))
            .await;

        let result = handle.await.unwrap();
        result_check(result);
    }
}

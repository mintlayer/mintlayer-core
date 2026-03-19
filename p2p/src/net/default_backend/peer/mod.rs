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

mod handshake_handler;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use tokio::{
    sync::mpsc::{self, unbounded_channel},
    task::JoinHandle,
};

use chainstate::ban_score::BanScore as _;
use common::{chain::ChainConfig, time_getter::TimeGetter};
use logging::log;
use networking::{
    error::NetworkingError,
    transport::{
        new_message_stream, ConnectedSocketInfo, MessageReader, MessageWriter, PeerStream,
        TransportSocket,
    },
};
use p2p_types::{peer_address::PeerAddress, services::Services, socket_addr_ext::SocketAddrExt};
use serialization::Encode as _;
use utils::tokio_spawn_in_current_tracing_span;

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    error::{P2pError, ProtocolError},
    message::{BlockSyncMessage, TransactionSyncMessage, WillDisconnectMessage},
    net::{
        default_backend::{
            peer::handshake_handler::HandshakeHandler,
            types::{BackendEvent, BackendObserver, MessageDebugLogSummary, MessageTag, PeerEvent},
        },
        types::PeerManagerMessageExt,
    },
    protocol::{ProtocolVersion, SupportedProtocolVersion},
    types::peer_id::PeerId,
};

use super::types::{can_send_will_disconnect, CategorizedMessage, HandshakeNonce, Message};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionInfo {
    Inbound,
    Outbound {
        handshake_nonce: HandshakeNonce,
        local_services_override: Option<Services>,
    },
}

pub struct Peer<T: TransportSocket> {
    /// Peer ID of the remote node
    peer_id: PeerId,

    /// Peer's remote address
    peer_address: PeerAddress,

    /// Chain config
    chain_config: Arc<ChainConfig>,

    p2p_config: Arc<P2pConfig>,

    connection_info: ConnectionInfo,

    /// Peer socket, split into reader and writer parts.
    socket_reader: MessageReader<T::Stream, Message>,
    socket_writer: MessageWriter<T::Stream, Message>,

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

    /// Observer object, used by tests.
    observer: Option<Arc<dyn BackendObserver + Send + Sync>>,
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
        peer_event_sender: mpsc::Sender<PeerEvent>,
        backend_event_receiver: mpsc::UnboundedReceiver<BackendEvent>,
        node_protocol_version: ProtocolVersion,
        time_getter: TimeGetter,
        observer: Option<Arc<dyn BackendObserver + Send + Sync>>,
    ) -> crate::Result<Self> {
        let peer_address = socket.remote_address()?.as_peer_address();

        let (socket_reader, socket_writer) =
            new_message_stream(socket, Some(*p2p_config.protocol_config.max_message_size));

        Ok(Self {
            peer_id,
            peer_address,
            connection_info,
            chain_config,
            p2p_config,
            socket_reader,
            socket_writer,
            peer_event_sender,
            backend_event_receiver,
            node_protocol_version,
            time_getter,
            observer,
        })
    }

    // Note: the channels used by this function to propagate messages to other parts of p2p
    // must be bounded; this is important to prevent DoS attacks.
    async fn handle_socket_msg(
        msg: Message,
        peer_event_sender: &mpsc::Sender<PeerEvent>,
        block_sync_msg_sender: &mpsc::Sender<BlockSyncMessage>,
        transaction_sync_msg_sender: &mpsc::Sender<TransactionSyncMessage>,
        sync_message_received: &mut bool,
    ) -> crate::Result<()> {
        log::debug!("Message received: {}", MessageDebugLogSummary(&msg));

        match msg.categorize() {
            CategorizedMessage::Handshake(_) => {
                log::error!("Peer sent unexpected handshake message");

                peer_event_sender
                    .send(PeerEvent::Misbehaved {
                        error: P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                            "Unexpected handshake message".to_owned(),
                        )),
                    })
                    .await?;
            }
            CategorizedMessage::PeerManagerMessage(msg) => {
                peer_event_sender
                    .send(PeerEvent::MessageReceived(
                        PeerManagerMessageExt::PeerManagerMessage(msg),
                    ))
                    .await?
            }
            CategorizedMessage::BlockSyncMessage(msg) => {
                if !*sync_message_received {
                    peer_event_sender
                        .send(PeerEvent::MessageReceived(
                            PeerManagerMessageExt::FirstSyncMessageReceived,
                        ))
                        .await?;
                    *sync_message_received = true;
                }

                block_sync_msg_sender.send(msg).await?;
            }
            CategorizedMessage::TransactionSyncMessage(msg) => {
                if !*sync_message_received {
                    peer_event_sender
                        .send(PeerEvent::MessageReceived(
                            PeerManagerMessageExt::FirstSyncMessageReceived,
                        ))
                        .await?;
                    *sync_message_received = true;
                }

                transaction_sync_msg_sender.send(msg).await?;
            }
        }

        Ok(())
    }

    async fn run_impl(self) -> crate::Result<()> {
        let Self {
            peer_id,
            peer_address,
            chain_config,
            p2p_config,
            connection_info,
            mut socket_reader,
            mut socket_writer,
            peer_event_sender,
            mut backend_event_receiver,
            node_protocol_version,
            time_getter,
            observer,
        } = self;

        let handshake_handler = HandshakeHandler::new(
            peer_address,
            connection_info,
            chain_config,
            Arc::clone(&p2p_config),
            node_protocol_version,
            time_getter,
        );

        // Run the handshake sequence first
        let common_protocol_version = handshake_handler
            .run_handshake(&peer_event_sender, &mut socket_reader, &mut socket_writer)
            .await?;

        // The channel to the sync manager peer task (set when the peer is accepted)
        let mut sync_msg_senders_opt = None;

        // Will be set to true once at least one BlockSyncMessage or TransactionSyncMessage has been
        // received from the peer.
        let mut sync_message_received = false;

        let (writer_cmd_sender, writer_cmd_receiver) = unbounded_channel();
        let (writer_event_sender, mut writer_event_receiver) = unbounded_channel();
        let writer_join_handle = spawn_writer(
            Arc::clone(&p2p_config),
            peer_id,
            common_protocol_version.0,
            socket_writer,
            writer_cmd_receiver,
            writer_event_sender,
            observer.clone(),
        );

        // Note: if the outer Option is set, an explicit disconnection should be initiated via
        // the writer task. Otherwise the writer task is supposed to be already closed.
        let reason_for_explicit_disconnect: Option<Option<DisconnectionReason>> = loop {
            tokio::select! {
                // Sending messages should have higher priority
                biased;

                event = backend_event_receiver.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    BackendEvent::Accepted{ block_sync_msg_sender, transaction_sync_msg_sender } => {
                        sync_msg_senders_opt = Some((block_sync_msg_sender, transaction_sync_msg_sender));
                    },
                    BackendEvent::SendMessage(message) => {
                        let message_tag: MessageTag = (&*message).into();
                        if let Err(_) = writer_cmd_sender.send(WriterCommand::SendMessage(message)) {
                            log::debug!(
                                "Socket writer task already closed when trying to send a message with tag {:?}",
                                message_tag
                            );
                            break None;
                        }
                    },
                    BackendEvent::Disconnect { reason } => {
                        break Some(reason);
                    },
                },
                event = writer_event_receiver.recv() => {
                    match event {
                        Some(WriterEvent::WriterClosed(result)) => {
                            match result {
                                Err(err) => {
                                    log::info!("Connection closed, reason: {err:?}");
                                }
                                Ok(()) => {
                                    // Note: this shouldn't really happen.
                                    log::warn!("Socket writer task closed without disconnection request");
                                }
                            }
                            break None;
                        },
                        None => {
                            // Note: this can happen if the writer task has panicked.
                            log::warn!("Socket writer task closed unexpectedly");
                            break None;
                        },
                    }
                }
                event = socket_reader.recv(), if sync_msg_senders_opt.is_some() => match event {
                    Ok(message) => {
                        if let Some(observer) = &observer {
                            observer.on_message_read(peer_id, &message);
                        }

                        let sync_msg_senders = sync_msg_senders_opt.as_mut().expect("sync_msg_senders_opt is some");
                        Self::handle_socket_msg(
                            message,
                            &peer_event_sender,
                            &sync_msg_senders.0,
                            &sync_msg_senders.1,
                            &mut sync_message_received,
                        ).await?;
                    }
                    Err(err) => {
                        let err = P2pError::NetworkingError(err);

                        let ban_score = err.ban_score();
                        if ban_score > 0 {
                            let send_result = peer_event_sender
                                .send(PeerEvent::Misbehaved { error: err.clone() })
                                .await;
                            if let Err(_) = send_result {
                                log::warn!("Cannot send PeerEvent::Misbehaved");
                            }
                        }

                        // Either return Some(Some(reason)) or None. I.e. if there is a disconnection reason associated
                        // with the obtained error, it's probably not just a connection issue, so it's better to
                        // do a proper disconnect, attempting to send the reason to the peer. Otherwise we're done.
                        let disconnection_reason = DisconnectionReason::from_error(&err, &p2p_config);
                        if let Some(disconnection_reason) =  disconnection_reason {
                            log::info!("Closing connection, reason: {err:?}");
                             break Some(Some(disconnection_reason));
                        }
                        else {
                            log::info!("Connection closed, reason: {err:?}");
                            break None;
                        }
                    }
                }
            }
        };

        if let Some(disconnection_reason) = reason_for_explicit_disconnect {
            let send_result = writer_cmd_sender.send(WriterCommand::Disconnect {
                reason: disconnection_reason,
            });
            match send_result {
                Ok(()) => {
                    let disconnect_result = tokio::time::timeout(
                        *p2p_config.backend_timeouts.disconnection_timeout,
                        async {
                            match writer_event_receiver.recv().await {
                                Some(WriterEvent::WriterClosed(result)) => {
                                    log::debug!("Socket writer closing confirmed with result: {result:?}");
                                },
                                None => {
                                    log::debug!("Socket writer task already closed when waiting for disconnection");
                                },
                            }
                        }
                    ).await;

                    match disconnect_result {
                        Ok(()) => {}
                        Err(_) => {
                            log::warn!("Disconnection request timed out");
                        }
                    }
                }
                Err(_) => {
                    log::debug!("Socket writer task already closed when trying to disconnect");
                }
            }
        }

        writer_join_handle.abort();

        Ok(())
    }

    #[tracing::instrument(skip_all, name = "", fields(peer_id = %self.peer_id), level = tracing::Level::ERROR)]
    pub async fn run(self) -> crate::Result<()> {
        let peer_event_sender = self.peer_event_sender.clone();
        let run_result = self.run_impl().await;
        let send_result = peer_event_sender.send(PeerEvent::ConnectionClosed).await;

        if let Err(_) = send_result {
            // Note: this situation is likely to happen if the connection is already closed,
            // so it's not really an error.
            log::debug!("Unable to send PeerEvent::ConnectionClosed to Backend");
        }

        run_result
    }
}

async fn maybe_send_will_disconnect<S: PeerStream>(
    reason: Option<DisconnectionReason>,
    peer_protocol_version: ProtocolVersion,
    socket_writer: &mut MessageWriter<S, Message>,
) -> crate::Result<()> {
    if can_send_will_disconnect(peer_protocol_version) {
        if let Some(reason) = reason {
            log::debug!("Sending WillDisconnect, reason: {:?}", reason);
            socket_writer
                .send(Message::WillDisconnect(WillDisconnectMessage {
                    reason: reason.to_string(),
                }))
                .await?;
        }
    }

    Ok(())
}

enum WriterCommand {
    SendMessage(Box<Message>),
    Disconnect { reason: Option<DisconnectionReason> },
}

enum WriterEvent {
    WriterClosed(crate::Result<()>),
}

fn spawn_writer<S: PeerStream + 'static>(
    p2p_config: Arc<P2pConfig>,
    peer_id: PeerId,
    common_protocol_version: SupportedProtocolVersion,
    socket_writer: MessageWriter<S, Message>,
    cmd_receiver: mpsc::UnboundedReceiver<WriterCommand>,
    event_sender: mpsc::UnboundedSender<WriterEvent>,
    observer: Option<Arc<dyn BackendObserver + Send + Sync>>,
) -> JoinHandle<()> {
    tokio_spawn_in_current_tracing_span(
        async move {
            let writer_result = writer_loop(
                &p2p_config,
                peer_id,
                common_protocol_version,
                socket_writer,
                cmd_receiver,
                observer,
            )
            .await;

            if let Err(_) = event_sender.send(WriterEvent::WriterClosed(writer_result)) {
                log::debug!("Peer task already closed");
            }
        },
        &format!("PeerSocketWriter[id={peer_id}]"),
    )
}

async fn writer_loop<S: PeerStream>(
    p2p_config: &P2pConfig,
    peer_id: PeerId,
    common_protocol_version: SupportedProtocolVersion,
    mut socket_writer: MessageWriter<S, Message>,
    mut cmd_receiver: mpsc::UnboundedReceiver<WriterCommand>,
    observer: Option<Arc<dyn BackendObserver + Send + Sync>>,
) -> crate::Result<()> {
    while let Some(cmd) = cmd_receiver.recv().await {
        match cmd {
            WriterCommand::SendMessage(message) => {
                log::debug!(
                    "Sending message {} with encoded size {}",
                    MessageDebugLogSummary(&*message),
                    message.encoded_size()
                );

                if let Some(observer) = &observer {
                    observer.on_message_write(peer_id, &message);
                }

                tokio::time::timeout(
                    *p2p_config.backend_timeouts.socket_write_timeout,
                    socket_writer.send(*message),
                )
                .await
                .map_err(|_| P2pError::NetworkingError(NetworkingError::SocketWriteTimedOut))??;
            }
            WriterCommand::Disconnect { reason } => {
                log::debug!("Disconnection requested, the reason is {:?}", reason);
                maybe_send_will_disconnect(
                    reason,
                    common_protocol_version.into(),
                    &mut socket_writer,
                )
                .await?;
                break;
            }
        }
    }

    Ok(())
}

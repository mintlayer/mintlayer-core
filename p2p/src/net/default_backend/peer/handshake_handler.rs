// Copyright (c) 2022-2026 RBB S.r.l
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

use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use chainstate::ban_score::BanScore;
use common::{chain::ChainConfig, primitives::time::Time, time_getter::TimeGetter};
use logging::log;
use networking::transport::{MessageReader, MessageWriter, PeerStream};
use p2p_types::{peer_address::PeerAddress, services::Services};

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    error::{ConnectionValidationError, P2pError, PeerError, ProtocolError},
    net::default_backend::types::{HandshakeMessage, Message, P2pTimestamp, PeerEvent, peer_event},
    protocol::{ProtocolVersion, SupportedProtocolVersion, choose_common_protocol_version},
};

use super::{ConnectionInfo, maybe_send_will_disconnect};

/// The chosen common protocol version; available only after the handshake has completed.
pub struct CommonProtocolVersion(pub SupportedProtocolVersion);

pub struct HandshakeHandler {
    /// Peer's remote address
    peer_address: PeerAddress,

    /// Chain config
    chain_config: Arc<ChainConfig>,

    p2p_config: Arc<P2pConfig>,

    connection_info: ConnectionInfo,

    /// The protocol version that this node is running. Normally this will be
    /// equal to default_networking_service::PREFERRED_PROTOCOL_VERSION, but it can be
    /// overridden for testing purposes.
    node_protocol_version: ProtocolVersion,

    /// Time getter
    time_getter: TimeGetter,
}

impl HandshakeHandler {
    pub fn new(
        peer_address: PeerAddress,
        connection_info: ConnectionInfo,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        node_protocol_version: ProtocolVersion,
        time_getter: TimeGetter,
    ) -> Self {
        Self {
            peer_address,
            connection_info,
            chain_config,
            p2p_config,
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
        // Note: in tests max_clock_diff can be very large, e.g. larger than local_time_start's
        // duration since epoch, so use saturating subtraction here.
        let accepted_peer_time_start = local_time_start.saturating_duration_sub(max_offset);
        let accepted_peer_time_end = (local_time_end + max_offset)
            .expect("Local time plus a small offset should not overflow");
        let accepted_peer_time = accepted_peer_time_start..=accepted_peer_time_end;

        let remote_time = Time::from_duration_since_epoch(remote_time.as_duration_since_epoch());

        utils::ensure!(
            accepted_peer_time.contains(&remote_time),
            P2pError::ConnectionValidationFailed(ConnectionValidationError::TimeDiff {
                remote_time,
                accepted_peer_time
            }),
        );

        Ok(())
    }

    /// Validate peer handshake info after Hello or HelloAck message has been received.
    async fn validate_handshake<S: PeerStream>(
        &self,
        handshake_init_time: Time,
        remote_time: P2pTimestamp,
        peer_protocol_version: ProtocolVersion,
        socket_writer: &mut MessageWriter<S, Message>,
    ) -> crate::Result<CommonProtocolVersion> {
        let recv_time = self.time_getter.get_time();
        let result = (|| {
            Self::validate_peer_time(
                &self.p2p_config,
                handshake_init_time,
                recv_time,
                remote_time,
            )?;

            choose_common_protocol_version(peer_protocol_version, self.node_protocol_version).ok_or(
                P2pError::ConnectionValidationFailed(
                    ConnectionValidationError::UnsupportedProtocol {
                        peer_protocol_version,
                    },
                ),
            )
        })();

        maybe_send_will_disconnect(
            DisconnectionReason::from_result(&result, &self.p2p_config),
            peer_protocol_version,
            socket_writer,
        )
        .await?;

        Ok(CommonProtocolVersion(result?))
    }

    async fn handshake_impl<S: PeerStream>(
        &self,
        peer_event_sender: &mpsc::Sender<PeerEvent>,
        socket_reader: &mut MessageReader<S, Message>,
        socket_writer: &mut MessageWriter<S, Message>,
    ) -> crate::Result<CommonProtocolVersion> {
        let init_time = self.time_getter.get_time();

        // Sending the remote socket address makes no sense and can leak private information when using a proxy
        let peer_address_to_send = if self.p2p_config.socks5_proxy.is_some() {
            None
        } else {
            Some(self.peer_address.clone())
        };

        let common_protocol_version = match self.connection_info {
            ConnectionInfo::Inbound => {
                let Message::Handshake(HandshakeMessage::Hello {
                    protocol_version: peer_protocol_version,
                    network,
                    services: remote_services,
                    user_agent,
                    software_version,
                    receiver_address: node_address_as_seen_by_peer,
                    current_time: remote_time,
                    handshake_nonce,
                }) = socket_reader.recv().await?
                else {
                    return Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected));
                };

                let common_protocol_version = self
                    .validate_handshake(
                        init_time,
                        remote_time,
                        peer_protocol_version,
                        socket_writer,
                    )
                    .await?;

                let local_services: Services = (*self.p2p_config.node_type).into();
                let common_services = local_services & remote_services;

                // Note: we send `PeerInfoReceived` to `Backend` before sending `HelloAck`
                // to the remote peer. `Backend` expects to receive `PeerInfoReceived` before
                // the outgoing connection has a chance to complete the handshake; specifically,
                // it relies on this fact when detecting self-connections.
                // Also note that we wait for the confirmation from `Backend` before sending
                // `HelloAck` to the peer. Without it a race is possible during self-connection
                // detection (which we've experienced in production), where the "outbound" part
                // of a self-connection may still be able to complete the handshake before the
                // "inbound" `PeerInfoReceived` manages to reach `Backend`.

                peer_event_sender
                    .send(PeerEvent::PeerInfoReceived(peer_event::PeerInfo {
                        protocol_version: common_protocol_version.0,
                        network,
                        common_services,
                        user_agent,
                        software_version,
                        node_address_as_seen_by_peer,
                        handshake_nonce,
                    }))
                    .await?;

                // Sync with `Backend` to ensure that the sent `PeerInfoReceived` has already been
                // processed by it before we complete the handshake.
                let (event_received_confirmation_sender, event_received_confirmation_receiver) =
                    oneshot::channel();
                peer_event_sender
                    .send(PeerEvent::Sync {
                        event_received_confirmation_sender,
                    })
                    .await?;
                let _ = event_received_confirmation_receiver.await;

                socket_writer
                    .send(Message::Handshake(HandshakeMessage::HelloAck {
                        protocol_version: self.node_protocol_version,
                        network: *self.chain_config.magic_bytes(),
                        user_agent: self.p2p_config.user_agent.clone(),
                        software_version: *self.chain_config.software_version(),
                        services: (*self.p2p_config.node_type).into(),
                        receiver_address: peer_address_to_send,
                        current_time: P2pTimestamp::from_time(self.time_getter.get_time()),
                    }))
                    .await?;

                common_protocol_version
            }
            ConnectionInfo::Outbound {
                handshake_nonce,
                local_services_override,
            } => {
                let local_services =
                    local_services_override.unwrap_or_else(|| (*self.p2p_config.node_type).into());

                socket_writer
                    .send(Message::Handshake(HandshakeMessage::Hello {
                        protocol_version: self.node_protocol_version,
                        network: *self.chain_config.magic_bytes(),
                        services: local_services,
                        user_agent: self.p2p_config.user_agent.clone(),
                        software_version: *self.chain_config.software_version(),
                        receiver_address: peer_address_to_send,
                        current_time: P2pTimestamp::from_time(init_time),
                        handshake_nonce,
                    }))
                    .await?;

                let hello_response = socket_reader.recv().await?;

                let Message::Handshake(HandshakeMessage::HelloAck {
                    protocol_version: peer_protocol_version,
                    network,
                    user_agent,
                    software_version,
                    services: remote_services,
                    receiver_address: node_address_as_seen_by_peer,
                    current_time: remote_time,
                }) = hello_response
                else {
                    if let Message::WillDisconnect(msg) = hello_response {
                        log::info!(
                            "Peer is going to disconnect us with the reason: '{}'",
                            msg.reason
                        );
                        return Err(P2pError::PeerError(PeerError::PeerWillDisconnect));
                    } else {
                        return Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected));
                    }
                };

                let common_protocol_version = self
                    .validate_handshake(
                        init_time,
                        remote_time,
                        peer_protocol_version,
                        socket_writer,
                    )
                    .await?;

                let common_services = local_services & remote_services;

                peer_event_sender
                    .send(PeerEvent::PeerInfoReceived(peer_event::PeerInfo {
                        protocol_version: common_protocol_version.0,
                        network,
                        common_services,
                        user_agent,
                        software_version,
                        node_address_as_seen_by_peer,
                        handshake_nonce,
                    }))
                    .await?;

                common_protocol_version
            }
        };

        Ok(common_protocol_version)
    }

    pub async fn run_handshake<S: PeerStream>(
        &self,
        peer_event_sender: &mpsc::Sender<PeerEvent>,
        socket_reader: &mut MessageReader<S, Message>,
        socket_writer: &mut MessageWriter<S, Message>,
    ) -> crate::Result<CommonProtocolVersion> {
        // handshake with remote peer and send peer's info to backend
        let handshake_timeout = *self.p2p_config.backend_timeouts.peer_handshake_timeout;
        let handshake_res = timeout(
            handshake_timeout,
            self.handshake_impl(peer_event_sender, socket_reader, socket_writer),
        )
        .await;

        match handshake_res {
            Ok(Ok(common_protocol_version)) => Ok(common_protocol_version),
            Ok(Err(err)) => {
                let ban_score = err.ban_score();
                log::debug!("Handshake failed: {err} (error ban score = {ban_score})");

                if ban_score > 0 {
                    let send_result = peer_event_sender
                        .send(PeerEvent::MisbehavedOnHandshake { error: err.clone() })
                        .await;
                    if send_result.is_err() {
                        log::error!("Cannot send PeerEvent::MisbehavedOnHandshake");
                    }
                }

                Err(err)
            }
            Err(_) => {
                log::debug!("Handshake timed out");
                Err(P2pError::ProtocolError(ProtocolError::Unresponsive))
            }
        }
    }
}

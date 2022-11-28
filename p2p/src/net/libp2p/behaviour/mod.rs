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

//! Network behaviour configuration for libp2p

pub mod connection_manager;
pub mod discovery;
pub mod sync_codec;

use std::{
    collections::{HashMap, VecDeque},
    iter,
    num::NonZeroU32,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use libp2p::{
    gossipsub::{self, Gossipsub, GossipsubConfigBuilder, MessageAuthenticity, ValidationMode},
    identify, identity, ping,
    request_response::{
        InboundFailure, OutboundFailure, ProtocolSupport, RequestId, RequestResponse,
        RequestResponseConfig, RequestResponseEvent, RequestResponseMessage, ResponseChannel,
    },
    swarm::{
        ConnectionHandler, IntoConnectionHandler, NetworkBehaviour as Libp2pNetworkBehaviour,
        NetworkBehaviourAction, NetworkBehaviourEventProcess, PollParameters,
    },
};

use common::chain::config::ChainConfig;
use logging::log;
use serialization::Decode;

use crate::{
    config,
    error::{P2pError, ProtocolError},
    message,
    net::libp2p::{
        behaviour::{
            connection_manager::types::{BehaviourEvent, ConnectionManagerEvent, ControlEvent},
            sync_codec::{
                message_types::{SyncRequest, SyncResponse},
                SyncMessagingCodec, SyncingProtocol,
            },
        },
        constants::{
            GOSSIPSUB_HEARTBEAT, GOSSIPSUB_MAX_TRANSMIT_SIZE, PING_INTERVAL, PING_MAX_RETRIES,
            PING_TIMEOUT,
        },
        types::{self, ConnectivityEvent, Libp2pBehaviourEvent, SyncingEvent},
    },
};

/// `Libp2pBehaviour` defines the protocols that communicate with peers, such as different streams
/// (sync, e.g., is a separate stream that's prefixed, at the stream-level, with `SyncingProtocol::protocol_name()`,
/// which is done through the demultiplexer of streams)
/// (identify, as another example, is a stream that's created by libp2p, and handles getting identifying information
/// of peers, like their peer public keys, addresses, supported protocols, etc)
///
/// Every "behaviour" below (besides those with `#[behaviour(ignore)]` on top), implement the `NetworkBehaviour` trait,
/// where this trait has methods that handle connections, streams, and other events.
///
/// As another example with explanation, the Request/Response protocol is used for syncing.
/// The implementation for that is done in:
///     `impl NetworkBehaviourEventProcess<RequestResponseEvent<SyncRequest, SyncResponse>> ...`
/// where we handle the request/response messages that libp2p demultiplexes for us
#[derive(libp2p::NetworkBehaviour)]
#[behaviour(
    out_event = "Libp2pBehaviourEvent",
    event_process = true,
    poll_method = "poll"
)]
pub struct Libp2pBehaviour {
    pub connmgr: connection_manager::ConnectionManager,
    pub identify: identify::Identify,
    pub discovery: discovery::DiscoveryManager,
    pub gossipsub: Gossipsub,
    pub ping: ping::Behaviour,
    pub sync: RequestResponse<SyncMessagingCodec>,

    #[behaviour(ignore)]
    pub events: VecDeque<Libp2pBehaviourEvent>,
    #[behaviour(ignore)]
    pub pending_reqs: HashMap<RequestId, ResponseChannel<SyncResponse>>,
    #[behaviour(ignore)]
    pub waker: Option<Waker>,
}

pub type Libp2pNetworkBehaviourAction = NetworkBehaviourAction<
    <Libp2pBehaviour as Libp2pNetworkBehaviour>::OutEvent,
    <Libp2pBehaviour as Libp2pNetworkBehaviour>::ConnectionHandler,
    <<<Libp2pBehaviour as Libp2pNetworkBehaviour>::ConnectionHandler
        as IntoConnectionHandler>::Handler as ConnectionHandler>::InEvent>;

impl Libp2pBehaviour {
    pub async fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
        id_keys: identity::Keypair,
    ) -> Self {
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(GOSSIPSUB_HEARTBEAT)
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
            .validate_messages()
            .build()
            .expect("configuration to be valid");

        let version = chain_config.version();
        let protocol = format!(
            "/mintlayer/{}.{}.{}-{:x}",
            version.major,
            version.minor,
            version.patch,
            chain_config.magic_bytes_as_u32(),
        );
        let mut req_cfg = RequestResponseConfig::default();
        req_cfg.set_request_timeout(Duration::from_secs(
            p2p_config.response_timeout.clone().into(),
        ));

        let behaviour = Libp2pBehaviour {
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_timeout(PING_TIMEOUT)
                    .with_interval(PING_INTERVAL)
                    .with_max_failures(
                        NonZeroU32::new(PING_MAX_RETRIES).expect("max failures > 0"),
                    ),
            ),
            identify: identify::Identify::new(identify::IdentifyConfig::new(
                protocol,
                id_keys.public(),
            )),
            sync: RequestResponse::new(
                SyncMessagingCodec(),
                iter::once((SyncingProtocol(), ProtocolSupport::Full)),
                req_cfg,
            ),
            gossipsub: Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid"),
            connmgr: connection_manager::ConnectionManager::new(),
            discovery: discovery::DiscoveryManager::new(Arc::clone(&p2p_config)).await,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            waker: None,
        };

        behaviour
    }

    fn add_event(&mut self, event: Libp2pBehaviourEvent) {
        self.events.push_back(event);

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<Libp2pNetworkBehaviourAction> {
        match &self.waker {
            Some(waker) => {
                if waker.will_wake(cx.waker()) {
                    self.waker = Some(cx.waker().clone());
                }
            }
            None => self.waker = Some(cx.waker().clone()),
        }

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
        }

        Poll::Pending
    }
}

impl NetworkBehaviourEventProcess<identify::IdentifyEvent> for Libp2pBehaviour {
    /// Libp2p handles retrieving identifying information from a new peer
    /// This function implements what to do with information received from a peer
    fn inject_event(&mut self, event: identify::IdentifyEvent) {
        match event {
            identify::IdentifyEvent::Error { peer_id, error } => {
                log::error!("libp2p-identify error for peer {peer_id}: {error}");
            }
            identify::IdentifyEvent::Received { peer_id, info } => {
                if let Err(err) = self.connmgr.register_identify_info(&peer_id, info) {
                    log::error!("Failed to register `IdentifyInfo` for peer {peer_id}: {err}",);
                }
            }
            identify::IdentifyEvent::Sent { peer_id } => {
                log::trace!("identify info sent to peer {peer_id}")
            }
            identify::IdentifyEvent::Pushed { peer_id } => {
                log::trace!("identify info pushed to peer {peer_id}")
            }
        }
    }
}

impl NetworkBehaviourEventProcess<ping::PingEvent> for Libp2pBehaviour {
    /// Libp2p handles sending low-level tcp pings to peers (with results that can be success/failure);
    /// we handle what to do with that here
    fn inject_event(&mut self, event: ping::PingEvent) {
        let ping::PingEvent { peer, result } = event;

        match result {
            Result::Ok(ping::Success::Ping { rtt }) => {
                // TODO: report rtt to swarm manager?
                log::debug!("peer {peer} responded to ping, rtt {rtt:?}");
            }
            Result::Ok(ping::Success::Pong) => {
                log::trace!("peer {peer} responded to pong");
            }
            Result::Err(ping::Failure::Timeout) => {
                log::warn!("ping timeout for peer {peer}");
                // TODO: add test for this
            }
            Result::Err(ping::Failure::Unsupported) => {
                log::error!("peer {peer} doesn't support libp2p::ping");
                // TODO: add test for this
            }
            Result::Err(ping::Failure::Other { error }) => {
                log::error!("unknown ping failure {error} from peer {peer}");
            }
        }
    }
}

impl NetworkBehaviourEventProcess<gossipsub::GossipsubEvent> for Libp2pBehaviour {
    /// Messages from Gossipsub (PubSub for us) are processed here, and then create an event to the PubSub module
    fn inject_event(&mut self, event: gossipsub::GossipsubEvent) {
        match event {
            gossipsub::GossipsubEvent::Unsubscribed { peer_id, topic } => {
                log::trace!("peer {peer_id} unsubscribed from topic {topic:?}");
            }
            gossipsub::GossipsubEvent::Subscribed { peer_id, topic } => {
                log::trace!("peer {peer_id} subscribed to topic {topic:?}");
            }
            gossipsub::GossipsubEvent::GossipsubNotSupported { peer_id } => {
                log::info!("peer {peer_id} does not support gossipsub");

                self.add_event(Libp2pBehaviourEvent::Connectivity(
                    ConnectivityEvent::Misbehaved {
                        peer_id,
                        error: P2pError::ProtocolError(ProtocolError::Incompatible),
                    },
                ))
            }
            gossipsub::GossipsubEvent::Message {
                propagation_source,
                message_id,
                message,
            } => {
                log::trace!(
                    "gossipsub message received, message id {:?}, propagation source {}",
                    message_id,
                    propagation_source
                );

                let announcement = match message::Announcement::decode(&mut &message.data[..]) {
                    Ok(data) => data,
                    Err(_) => {
                        log::warn!(
                            "received invalid message, propagation source: {:?}",
                            propagation_source
                        );

                        return self.add_event(Libp2pBehaviourEvent::Connectivity(
                            ConnectivityEvent::Misbehaved {
                                peer_id: propagation_source,
                                error: P2pError::ProtocolError(ProtocolError::InvalidMessage),
                            },
                        ));
                    }
                };

                self.add_event(Libp2pBehaviourEvent::Syncing(SyncingEvent::Announcement {
                    peer_id: propagation_source,
                    message_id,
                    announcement: Box::new(announcement),
                }));
            }
        }
    }
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<SyncRequest, SyncResponse>>
    for Libp2pBehaviour
{
    /// handle all request/response messages that have to do with syncing blocks
    fn inject_event(&mut self, event: RequestResponseEvent<SyncRequest, SyncResponse>) {
        match event {
            RequestResponseEvent::Message { peer, message } => match message {
                RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    self.pending_reqs.insert(request_id, channel);
                    self.add_event(Libp2pBehaviourEvent::Syncing(
                        types::SyncingEvent::Request {
                            peer_id: peer,
                            request_id,
                            request: Box::new(request),
                        },
                    ));
                }
                RequestResponseMessage::Response {
                    request_id,
                    response,
                } => {
                    self.add_event(Libp2pBehaviourEvent::Syncing(
                        types::SyncingEvent::Response {
                            peer_id: peer,
                            request_id,
                            response: Box::new(response),
                        },
                    ));
                }
            },
            RequestResponseEvent::ResponseSent {
                peer: _,
                request_id,
            } => {
                log::debug!("response sent, request id {request_id:?}");
            }
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => match error {
                OutboundFailure::Timeout => {
                    log::debug!("OutboundFailure::Timeout for {peer} for {request_id:?}: {error}");
                }
                OutboundFailure::ConnectionClosed => {
                    if let Err(err) = self.connmgr.handle_connection_closed(&peer) {
                        log::error!(
                            "Failed to handle `ConnectionClosed` event for peer {peer}: {err}"
                        );
                    }
                }
                OutboundFailure::DialFailure => {
                    log::error!("CRITICAL: syncing code tried to dial peer");
                }
                OutboundFailure::UnsupportedProtocols => {
                    log::error!(
                        "CRITICAL: unsupported protocol should have been caught by peer manager"
                    );
                }
            },
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => match error {
                InboundFailure::Timeout => {
                    log::debug!("InboundFailure::Timeout for {peer} for {request_id:?}: {error}");
                }
                InboundFailure::ConnectionClosed => {
                    if let Err(err) = self.connmgr.handle_connection_closed(&peer) {
                        log::error!(
                            "Failed to handle `ConnectionClosed` event for peer {peer}: {err}",
                        );
                    }
                }
                InboundFailure::ResponseOmission => {
                    log::error!("CRITICAL(??): response omitted!");
                }
                InboundFailure::UnsupportedProtocols => {
                    log::error!(
                        "CRITICAL: unsupported protocol should have been caught by peer manager"
                    );
                }
            },
        }
    }
}

impl NetworkBehaviourEventProcess<ConnectionManagerEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: ConnectionManagerEvent) {
        match event {
            ConnectionManagerEvent::Behaviour(event) => match event {
                BehaviourEvent::InboundAccepted { address, peer_info } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::InboundAccepted { address, peer_info },
                    ))
                }
                BehaviourEvent::OutboundAccepted { address, peer_info } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::OutboundAccepted { address, peer_info },
                    ))
                }
                BehaviourEvent::ConnectionClosed { peer_id } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::ConnectionClosed { peer_id },
                    ))
                }
                BehaviourEvent::ConnectionError { address, error } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::ConnectionError { address, error },
                    ))
                }
            },
            ConnectionManagerEvent::Control(event) => match event {
                ControlEvent::CloseConnection { peer_id } => self.add_event(
                    Libp2pBehaviourEvent::Control(types::ControlEvent::CloseConnection { peer_id }),
                ),
            },
        }
    }
}

impl NetworkBehaviourEventProcess<discovery::DiscoveryEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: discovery::DiscoveryEvent) {
        match event {
            discovery::DiscoveryEvent::Discovered(peers) => {
                self.add_event(Libp2pBehaviourEvent::Connectivity(
                    ConnectivityEvent::Discovered { peers },
                ));
            }
            discovery::DiscoveryEvent::Expired(peers) => {
                self.add_event(Libp2pBehaviourEvent::Connectivity(
                    ConnectivityEvent::Expired { peers },
                ));
            }
        }
    }
}

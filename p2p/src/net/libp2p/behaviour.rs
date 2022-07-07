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

//! Network behaviour configuration for libp2p

use crate::{
    message,
    net::{
        self,
        libp2p::{
            connectivity::{
                self,
                types::{BehaviourEvent, ConnectionManagerEvent, ControlEvent},
            },
            constants::*,
            discovery,
            sync::*,
            types::{self, ConnectivityEvent, Libp2pBehaviourEvent, PubSubEvent},
        },
    },
};
use common::chain::config::ChainConfig;
use libp2p::{
    gossipsub::{self, Gossipsub, GossipsubConfigBuilder, MessageAuthenticity, ValidationMode},
    identify, identity, ping,
    request_response::*,
    swarm::{
        ConnectionHandler, IntoConnectionHandler, NetworkBehaviour as Libp2pNetworkBehaviour,
        NetworkBehaviourAction, NetworkBehaviourEventProcess, PollParameters,
    },
    NetworkBehaviour,
};
use logging::log;
use serialization::Decode;
use std::{
    collections::{HashMap, VecDeque},
    iter,
    num::NonZeroU32,
    sync::Arc,
    task::{Context, Poll, Waker},
};

#[derive(NetworkBehaviour)]
#[behaviour(
    out_event = "Libp2pBehaviourEvent",
    event_process = true,
    poll_method = "poll"
)]
pub struct Libp2pBehaviour {
    pub gossipsub: Gossipsub,
    pub ping: ping::Behaviour,
    pub identify: identify::Identify,
    pub sync: RequestResponse<SyncingCodec>,
    pub connmgr: connectivity::ConnectionManager,
    pub discovery: discovery::DiscoveryManager,

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
        config: Arc<ChainConfig>,
        id_keys: identity::Keypair,
        enable_mdns: bool,
    ) -> Self {
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(GOSSIPSUB_HEARTBEAT)
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
            .validate_messages()
            .build()
            .expect("configuration to be valid");

        let version = config.version();
        let protocol = format!(
            "/mintlayer/{}.{}.{}-{:x}",
            version.major,
            version.minor,
            version.patch,
            config.magic_bytes_as_u32(),
        );
        let mut req_cfg = RequestResponseConfig::default();
        req_cfg.set_request_timeout(REQ_RESP_TIMEOUT);

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
                SyncingCodec(),
                iter::once((SyncingProtocol(), ProtocolSupport::Full)),
                req_cfg,
            ),
            gossipsub: Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid"),
            connmgr: connectivity::ConnectionManager::new(),
            discovery: discovery::DiscoveryManager::new(enable_mdns).await,
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
    fn inject_event(&mut self, event: identify::IdentifyEvent) {
        match event {
            identify::IdentifyEvent::Error { peer_id, error } => {
                log::error!("libp2p-identify error for peer {}: {}", peer_id, error);
            }
            identify::IdentifyEvent::Received { peer_id, info } => {
                if let Err(err) = self.connmgr.register_identify_info(&peer_id, info) {
                    log::error!(
                        "Failed to register `IdentifyInfo` for peer {}: {}",
                        peer_id,
                        err
                    );
                }
            }
            identify::IdentifyEvent::Sent { peer_id } => {
                log::trace!("identify info sent to peer {:?}", peer_id)
            }
            identify::IdentifyEvent::Pushed { peer_id } => {
                log::trace!("identify info pushed to peer {:?}", peer_id)
            }
        }
    }
}

impl NetworkBehaviourEventProcess<ping::PingEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: ping::PingEvent) {
        match event {
            ping::Event {
                peer,
                result: Result::Ok(ping::Success::Ping { rtt }),
            } => {
                // TODO: report rtt to swarm manager?
                log::debug!("peer {} responded to ping, rtt {:?}", peer, rtt);
            }
            ping::Event {
                peer,
                result: Result::Ok(ping::Success::Pong),
            } => {
                log::debug!("peer {} responded to pong", peer);
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Timeout),
            } => {
                log::warn!("ping timeout for peer {}", peer);
                // TODO: add test for this
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Unsupported),
            } => {
                log::error!("peer {} doesn't support libp2p::ping", peer);
                // TODO: add test for this
            }
            ping::Event {
                peer: _,
                result: Result::Err(ping::Failure::Other { error }),
            } => {
                log::error!("unknown ping failure: {:?}", error);
            }
        }
    }
}

impl NetworkBehaviourEventProcess<gossipsub::GossipsubEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: gossipsub::GossipsubEvent) {
        match event {
            gossipsub::GossipsubEvent::Unsubscribed { peer_id, topic } => {
                log::trace!("peer {} unsubscribed from topic {:?}", peer_id, topic);
            }
            gossipsub::GossipsubEvent::Subscribed { peer_id, topic } => {
                log::trace!("peer {} subscribed to topic {:?}", peer_id, topic);
            }
            gossipsub::GossipsubEvent::GossipsubNotSupported { peer_id } => {
                // TODO: should not be possible with mintlayer, disconnect?
                log::info!("peer {} does not support gossipsub", peer_id);

                self.add_event(Libp2pBehaviourEvent::Connectivity(
                    ConnectivityEvent::Misbehaved {
                        peer_id,
                        behaviour: 0,
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

                        // TODO: implement reputation
                        return self.add_event(Libp2pBehaviourEvent::Connectivity(
                            ConnectivityEvent::Misbehaved {
                                peer_id: propagation_source,
                                behaviour: 0,
                            },
                        ));
                    }
                };

                self.add_event(Libp2pBehaviourEvent::PubSub(PubSubEvent::Announcement {
                    peer_id: propagation_source,
                    message_id,
                    announcement,
                }));
            }
        }
    }
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<SyncRequest, SyncResponse>>
    for Libp2pBehaviour
{
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
                log::debug!("response sent, request id {:?}", request_id);
            }
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                match error {
                    OutboundFailure::Timeout => {
                        self.add_event(Libp2pBehaviourEvent::Syncing(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            error: net::types::RequestResponseError::Timeout,
                        }));
                    }
                    OutboundFailure::ConnectionClosed => {
                        if let Err(err) = self.connmgr.handle_connection_closed(&peer) {
                            log::error!(
                                "Failed to handle `ConnectionClosed` event for peer {}: {}",
                                peer,
                                err
                            );
                        }
                    }
                    OutboundFailure::DialFailure => {
                        log::error!("CRITICAL: syncing code tried to dial peer");
                    }
                    OutboundFailure::UnsupportedProtocols => {
                        log::error!("CRITICAL: unsupported protocol should have been caught by peer manager");
                    }
                }
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                match error {
                    InboundFailure::Timeout => {
                        self.add_event(Libp2pBehaviourEvent::Syncing(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            error: net::types::RequestResponseError::Timeout,
                        }));
                    }
                    InboundFailure::ConnectionClosed => {
                        if let Err(err) = self.connmgr.handle_connection_closed(&peer) {
                            log::error!(
                                "Failed to handle `ConnectionClosed` event for peer {}: {}",
                                peer,
                                err
                            );
                        }
                    }
                    InboundFailure::ResponseOmission => {
                        log::error!("CRITICAL(??): response omitted!");
                    }
                    InboundFailure::UnsupportedProtocols => {
                        log::error!("CRITICAL: unsupported protocol should have been caught by peer manager");
                    }
                }
            }
        }
    }
}

impl NetworkBehaviourEventProcess<ConnectionManagerEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: ConnectionManagerEvent) {
        match event {
            ConnectionManagerEvent::Behaviour(event) => match event {
                BehaviourEvent::InboundAccepted { addr, peer_info } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::IncomingConnection { addr, peer_info },
                    ))
                }
                BehaviourEvent::OutboundAccepted { addr, peer_info } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::ConnectionAccepted { addr, peer_info },
                    ))
                }
                BehaviourEvent::ConnectionClosed { peer_id } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::ConnectionClosed { peer_id },
                    ))
                }
                BehaviourEvent::ConnectionError { addr, error } => {
                    self.add_event(Libp2pBehaviourEvent::Connectivity(
                        ConnectivityEvent::ConnectionError { addr, error },
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

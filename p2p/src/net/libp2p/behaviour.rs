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
            constants::*,
            sync::*,
            types::{self, ConnectivityEvent, Libp2pBehaviourEvent, PubSubEvent},
        },
    },
};
use common::chain::config::ChainConfig;
use libp2p::{
    core::PeerId,
    gossipsub::{self, Gossipsub, GossipsubConfigBuilder, MessageAuthenticity, ValidationMode},
    identify, identity, mdns, ping,
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
    collections::{HashMap, HashSet, VecDeque},
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
    pub mdns: mdns::Mdns,
    pub gossipsub: Gossipsub,
    pub ping: ping::Behaviour,
    pub identify: identify::Identify,
    pub sync: RequestResponse<SyncingCodec>,

    /// Should mDNS events be relayed to front-end
    #[behaviour(ignore)]
    pub relay_mdns: bool,

    #[behaviour(ignore)]
    pub events: VecDeque<Libp2pBehaviourEvent>,

    #[behaviour(ignore)]
    pub pending_reqs: HashMap<RequestId, ResponseChannel<SyncResponse>>,

    // TODO: connectionmanager
    #[behaviour(ignore)]
    pub(super) established_conns: HashSet<PeerId>,

    // TODO: connectionmanager
    #[behaviour(ignore)]
    pub pending_conns: HashMap<PeerId, types::PendingState>,

    #[behaviour(ignore)]
    pub waker: Option<Waker>,
}

type Libp2pNetworkBehaviourAction = NetworkBehaviourAction<
    <Libp2pBehaviour as Libp2pNetworkBehaviour>::OutEvent,
    <Libp2pBehaviour as Libp2pNetworkBehaviour>::ConnectionHandler,
    <<<Libp2pBehaviour as Libp2pNetworkBehaviour>::ConnectionHandler
        as IntoConnectionHandler>::Handler as ConnectionHandler>::InEvent>;

impl Libp2pBehaviour {
    pub async fn new(
        config: Arc<ChainConfig>,
        id_keys: identity::Keypair,
        relay_mdns: bool,
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
            mdns: mdns::Mdns::new(Default::default()).await.expect("mDNS to succeed"),
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
            relay_mdns,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            established_conns: HashSet::new(),
            pending_conns: HashMap::new(),
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
                log::error!(
                    "libp2p-identify error occurred with connected peer ({:?}): {:?}",
                    peer_id,
                    error
                );

                self.add_event(Libp2pBehaviourEvent::Connectivity(
                    ConnectivityEvent::Error {
                        peer_id,
                        error: error.into(),
                    },
                ));
            }
            identify::IdentifyEvent::Sent { peer_id } => {
                log::debug!("identify info sent to peer {:?}", peer_id);
            }
            identify::IdentifyEvent::Pushed { peer_id } => {
                log::debug!("identify info pushed to peer {:?}", peer_id);
            }
            identify::IdentifyEvent::Received { peer_id, info } => {
                // TODO: update swarm manager?
                // TODO: connection manager
                if self.established_conns.contains(&peer_id) {
                    log::trace!("peer {:?} resent their info: {:#?}", peer_id, info);
                    return;
                }

                // TODO: implement connection manager
                match self.pending_conns.remove(&peer_id) {
                    None => {
                        // TODO: report peer id to swarm manager
                        log::error!("pending connection for peer {:?} does not exist", peer_id);
                    }
                    Some(types::PendingState::Dialed(_addr)) => {
                        // TODO: report peer id to swarm manager
                        log::error!("received peer info before connection was established");
                    }
                    Some(types::PendingState::OutboundAccepted(addr)) => {
                        self.established_conns.insert(peer_id);
                        self.add_event(Libp2pBehaviourEvent::Connectivity(
                            ConnectivityEvent::ConnectionAccepted {
                                addr,
                                peer_info: Box::new(info),
                            },
                        ));
                    }
                    Some(types::PendingState::InboundAccepted(addr)) => {
                        self.established_conns.insert(peer_id);
                        self.add_event(Libp2pBehaviourEvent::Connectivity(
                            ConnectivityEvent::IncomingConnection {
                                addr,
                                peer_info: Box::new(info),
                            },
                        ));
                    }
                }
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
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Unsupported),
            } => {
                log::error!("peer {} doesn't support libp2p::ping", peer);
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
                // TODO: swarm manager??
                log::trace!("peer {} unsubscribed from topic {:?}", peer_id, topic);
            }
            gossipsub::GossipsubEvent::Subscribed { peer_id, topic } => {
                // TODO: swarm manager??
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

                let message = match message::Message::decode(&mut &message.data[..]) {
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

                self.add_event(Libp2pBehaviourEvent::PubSub(PubSubEvent::MessageReceived {
                    peer_id: propagation_source,
                    message,
                    message_id,
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
                        self.add_event(Libp2pBehaviourEvent::Syncing(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            // TODO: connection manager
                            error: net::types::RequestResponseError::ConnectionClosed,
                        }));
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
                        self.add_event(Libp2pBehaviourEvent::Syncing(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            error: net::types::RequestResponseError::ConnectionClosed,
                        }));
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

impl NetworkBehaviourEventProcess<mdns::MdnsEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: mdns::MdnsEvent) {
        // TODO: remove this ugly hack
        if !self.relay_mdns {
            return;
        }

        match event {
            mdns::MdnsEvent::Discovered(peers) => {
                self.add_event(Libp2pBehaviourEvent::Connectivity(
                    ConnectivityEvent::Discovered {
                        peers: peers.collect(),
                    },
                ));
            }
            mdns::MdnsEvent::Expired(expired) => {
                self.add_event(Libp2pBehaviourEvent::Connectivity(
                    ConnectivityEvent::Expired {
                        peers: expired.collect(),
                    },
                ));
            }
        }
    }
}

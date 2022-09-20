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

pub mod behaviour_wrapper;
pub mod connection_manager;
pub mod discovery;
pub mod sync_codec;

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    task::{Context, Poll, Waker},
};

use libp2p::{
    core::connection::ConnectionId,
    gossipsub::GossipsubEvent,
    identify::IdentifyEvent,
    identity::Keypair,
    ping,
    request_response::*,
    swarm::{
        ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
        PollParameters,
    },
    PeerId,
};

use common::chain::config::ChainConfig;
use logging::log;
use serialization::Decode;

use crate::{
    config::P2pConfig,
    error::{P2pError, ProtocolError},
    message,
    net::{
        self,
        libp2p::{
            behaviour::{
                behaviour_wrapper::{NetworkBehaviourWrapper, NetworkBehaviourWrapperEvent},
                connection_manager::types::{BehaviourEvent, ConnectionManagerEvent, ControlEvent},
                sync_codec::message_types::SyncResponse,
            },
            types::{self, ConnectivityEvent, Libp2pBehaviourEvent, PubSubEvent},
        },
    },
};

/// `Libp2pBehaviour` defines the protocols that communicate with peers, such as different streams
/// (sync, e.g., is a separate stream that's prefixed, at the stream-level, with `SyncingProtocol::protocol_name()`,
/// which is done through the demultiplexer of streams)
/// (identify, as another example, is a stream that's created by libp2p, and handles getting identifying information
/// of peers, like their peer public keys, addresses, supported protocols, etc)
///
/// As another example with explanation, the Request/Response protocol is used for syncing.
/// The implementation for that is done in:
///     `impl NetworkBehaviourEventProcess<RequestResponseEvent<SyncRequest, SyncResponse>> ...`
/// where we handle the request/response messages that libp2p demultiplexes for us
pub struct Libp2pBehaviour {
    pub behaviour: NetworkBehaviourWrapper,
    pub events: VecDeque<Libp2pBehaviourEvent>,
    pub pending_reqs: HashMap<RequestId, ResponseChannel<SyncResponse>>,
    pub waker: Option<Waker>,
}

pub type Libp2pNetworkBehaviourAction = NetworkBehaviourAction<
    <Libp2pBehaviour as NetworkBehaviour>::OutEvent,
    <Libp2pBehaviour as NetworkBehaviour>::ConnectionHandler,
    <<<Libp2pBehaviour as NetworkBehaviour>::ConnectionHandler
        as IntoConnectionHandler>::Handler as ConnectionHandler>::InEvent>;

impl Libp2pBehaviour {
    pub async fn new(
        config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        id_keys: Keypair,
    ) -> Self {
        let behaviour = NetworkBehaviourWrapper::new(config, p2p_config, id_keys).await;

        Self {
            behaviour,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            waker: None,
        }
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

impl NetworkBehaviour for Libp2pBehaviour {
    type ConnectionHandler = <NetworkBehaviourWrapper as NetworkBehaviour>::ConnectionHandler;
    type OutEvent = Libp2pBehaviourEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        self.behaviour.new_handler()
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
        self.behaviour.inject_event(peer_id, connection, event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        loop {
            // TODO: FIXME: Split?..
            match self.behaviour.poll(cx, params) {
                Poll::Ready(NetworkBehaviourAction::GenerateEvent(event)) => match event {
                    NetworkBehaviourWrapperEvent::Identify(event) => match event {
                        IdentifyEvent::Error { peer_id, error } => {
                            log::error!("libp2p-identify error for peer {peer_id}: {error}");
                        }
                        IdentifyEvent::Received { peer_id, info } => {
                            if let Err(err) =
                                self.behaviour.connmgr.register_identify_info(&peer_id, info)
                            {
                                log::error!(
                                    "Failed to register `IdentifyInfo` for peer {peer_id}: {err}",
                                );
                            }
                        }
                        IdentifyEvent::Sent { peer_id } => {
                            log::trace!("identify info sent to peer {peer_id}")
                        }
                        IdentifyEvent::Pushed { peer_id } => {
                            log::trace!("identify info pushed to peer {peer_id}")
                        }
                    },
                    NetworkBehaviourWrapperEvent::Ping(event) => {
                        let ping::PingEvent { peer, result } = event;
                        match result {
                            Ok(ping::Success::Ping { rtt }) => {
                                // TODO: report rtt to swarm manager?
                                log::debug!("peer {peer} responded to ping, rtt {rtt:?}");
                            }
                            Ok(ping::Success::Pong) => {
                                log::trace!("peer {peer} responded to pong");
                            }
                            Err(ping::Failure::Timeout) => {
                                log::warn!("ping timeout for peer {peer}");
                                // TODO: add test for this
                            }
                            Err(ping::Failure::Unsupported) => {
                                log::error!("peer {peer} doesn't support libp2p::ping");
                                // TODO: add test for this
                            }
                            Err(ping::Failure::Other { error }) => {
                                log::error!("unknown ping failure {error} from peer {peer}");
                            }
                        }
                    }
                    NetworkBehaviourWrapperEvent::Gossipsub(event) => match event {
                        GossipsubEvent::Unsubscribed { peer_id, topic } => {
                            log::trace!("peer {peer_id} unsubscribed from topic {topic:?}");
                        }
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            log::trace!("peer {peer_id} subscribed to topic {topic:?}");
                        }
                        GossipsubEvent::GossipsubNotSupported { peer_id } => {
                            log::info!("peer {peer_id} does not support gossipsub");

                            self.add_event(Libp2pBehaviourEvent::Connectivity(
                                ConnectivityEvent::Misbehaved {
                                    peer_id,
                                    error: P2pError::ProtocolError(ProtocolError::Incompatible),
                                },
                            ))
                        }
                        GossipsubEvent::Message {
                            propagation_source,
                            message_id,
                            message,
                        } => {
                            log::trace!("gossipsub message received, message id {message_id:?}, propagation source {propagation_source}");

                            let announcement =
                                match message::Announcement::decode(&mut &message.data[..]) {
                                    Ok(data) => data,
                                    Err(_) => {
                                        log::warn!(
                                            "received invalid message, propagation source: {:?}",
                                            propagation_source
                                        );

                                        self.add_event(Libp2pBehaviourEvent::Connectivity(
                                            ConnectivityEvent::Misbehaved {
                                                peer_id: propagation_source,
                                                error: P2pError::ProtocolError(
                                                    ProtocolError::InvalidMessage,
                                                ),
                                            },
                                        ));
                                        continue;
                                    }
                                };
                            self.add_event(Libp2pBehaviourEvent::PubSub(
                                PubSubEvent::Announcement {
                                    peer_id: propagation_source,
                                    message_id,
                                    announcement,
                                },
                            ));
                        }
                    },
                    NetworkBehaviourWrapperEvent::Sync(event) => match event {
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
                                self.add_event(Libp2pBehaviourEvent::Syncing(
                                    types::SyncingEvent::Error {
                                        peer_id: peer,
                                        request_id,
                                        error: net::types::RequestResponseError::Timeout,
                                    },
                                ));
                            }
                            OutboundFailure::ConnectionClosed => {
                                if let Err(err) =
                                    self.behaviour.connmgr.handle_connection_closed(&peer)
                                {
                                    log::error!(
                                "Failed to handle `ConnectionClosed` event for peer {peer}: {err}"
                            );
                                }
                            }
                            OutboundFailure::DialFailure => {
                                log::error!("CRITICAL: syncing code tried to dial peer");
                            }
                            OutboundFailure::UnsupportedProtocols => {
                                log::error!("CRITICAL: unsupported protocol should have been caught by peer manager");
                            }
                        },
                        RequestResponseEvent::InboundFailure {
                            peer,
                            request_id,
                            error,
                        } => match error {
                            InboundFailure::Timeout => {
                                self.add_event(Libp2pBehaviourEvent::Syncing(
                                    types::SyncingEvent::Error {
                                        peer_id: peer,
                                        request_id,
                                        error: net::types::RequestResponseError::Timeout,
                                    },
                                ));
                            }
                            InboundFailure::ConnectionClosed => {
                                if let Err(err) =
                                    self.behaviour.connmgr.handle_connection_closed(&peer)
                                {
                                    log::error!(
                                "Failed to handle `ConnectionClosed` event for peer {peer}: {err}",
                            );
                                }
                            }
                            InboundFailure::ResponseOmission => {
                                log::error!("CRITICAL(??): response omitted!");
                            }
                            InboundFailure::UnsupportedProtocols => {
                                log::error!("CRITICAL: unsupported protocol should have been caught by peer manager");
                            }
                        },
                    },
                    NetworkBehaviourWrapperEvent::Connmgr(event) => match event {
                        ConnectionManagerEvent::Behaviour(event) => match event {
                            BehaviourEvent::InboundAccepted { address, peer_info } => self
                                .add_event(Libp2pBehaviourEvent::Connectivity(
                                    ConnectivityEvent::InboundAccepted { address, peer_info },
                                )),
                            BehaviourEvent::OutboundAccepted { address, peer_info } => self
                                .add_event(Libp2pBehaviourEvent::Connectivity(
                                    ConnectivityEvent::OutboundAccepted { address, peer_info },
                                )),
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
                            ControlEvent::CloseConnection { peer_id } => {
                                self.add_event(Libp2pBehaviourEvent::Control(
                                    types::ControlEvent::CloseConnection { peer_id },
                                ))
                            }
                        },
                    },
                    NetworkBehaviourWrapperEvent::Discovery(event) => match event {
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
                    },
                },
                Poll::Ready(_) => continue,
                Poll::Pending => break,
            }
        }
        Libp2pBehaviour::poll(self, cx, params)
    }
}

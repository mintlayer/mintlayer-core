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
#![allow(clippy::type_complexity)]
use libp2p::{
    core::{connection, either, ConnectedPoint, Multiaddr, PeerId},
    gossipsub::{Gossipsub, GossipsubEvent},
    mdns::{Mdns, MdnsEvent},
    streaming::{IdentityCodec, Streaming, StreamingEvent},
    swarm::{
        DialError, IntoProtocolsHandler, IntoProtocolsHandlerSelect, NetworkBehaviour,
        NetworkBehaviourAction, PollParameters, ProtocolsHandler,
    },
};
use std::task::Poll;

pub struct ComposedBehaviour {
    pub streaming: Streaming<IdentityCodec>,
    pub mdns: Mdns,
    pub gossipsub: Gossipsub,
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ComposedEvent {
    StreamingEvent(StreamingEvent<IdentityCodec>),
    MdnsEvent(MdnsEvent),
    GossipsubEvent(GossipsubEvent),
}

impl From<StreamingEvent<IdentityCodec>> for ComposedEvent {
    fn from(event: StreamingEvent<IdentityCodec>) -> Self {
        ComposedEvent::StreamingEvent(event)
    }
}

impl From<MdnsEvent> for ComposedEvent {
    fn from(event: MdnsEvent) -> Self {
        ComposedEvent::MdnsEvent(event)
    }
}

impl From<GossipsubEvent> for ComposedEvent {
    fn from(event: GossipsubEvent) -> Self {
        ComposedEvent::GossipsubEvent(event)
    }
}

impl NetworkBehaviour for ComposedBehaviour
where
    Streaming<IdentityCodec>: NetworkBehaviour,
    ComposedEvent: From<<Streaming<IdentityCodec> as NetworkBehaviour>::OutEvent>,
    Mdns: NetworkBehaviour,
    ComposedEvent: From<<Mdns as NetworkBehaviour>::OutEvent>,
    Gossipsub: NetworkBehaviour,
    ComposedEvent: From<<Gossipsub as NetworkBehaviour>::OutEvent>,
{
    type ProtocolsHandler = IntoProtocolsHandlerSelect<
        IntoProtocolsHandlerSelect<
            <Streaming<IdentityCodec> as NetworkBehaviour>::ProtocolsHandler,
            <Mdns as NetworkBehaviour>::ProtocolsHandler,
        >,
        <Gossipsub as NetworkBehaviour>::ProtocolsHandler,
    >;
    type OutEvent = ComposedEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        IntoProtocolsHandler::select(
            IntoProtocolsHandler::select(self.streaming.new_handler(), self.mdns.new_handler()),
            self.gossipsub.new_handler(),
        )
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let mut out = Vec::new();
        out.extend(self.streaming.addresses_of_peer(peer_id));
        out.extend(self.mdns.addresses_of_peer(peer_id));
        out.extend(self.gossipsub.addresses_of_peer(peer_id));
        out
    }

    fn inject_connected(&mut self, peer_id: &PeerId) {
        self.streaming.inject_connected(peer_id);
        self.mdns.inject_connected(peer_id);
        self.gossipsub.inject_connected(peer_id);
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId) {
        self.streaming.inject_disconnected(peer_id);
        self.mdns.inject_disconnected(peer_id);
        self.gossipsub.inject_disconnected(peer_id);
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &connection::ConnectionId,
        endpoint: &ConnectedPoint,
        errors: Option<&Vec<Multiaddr>>,
    ) {
        self.streaming
            .inject_connection_established(peer_id, connection_id, endpoint, errors);

        self.mdns
            .inject_connection_established(peer_id, connection_id, endpoint, errors);

        self.gossipsub
            .inject_connection_established(peer_id, connection_id, endpoint, errors);
    }

    fn inject_address_change(
        &mut self,
        peer_id: &PeerId,
        connection_id: &connection::ConnectionId,
        old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        self.streaming.inject_address_change(peer_id, connection_id, old, new);
        self.mdns.inject_address_change(peer_id, connection_id, old, new);
        self.gossipsub.inject_address_change(peer_id, connection_id, old, new);
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        connection_id: &connection::ConnectionId,
        endpoint: &ConnectedPoint,
        handlers: <Self::ProtocolsHandler as IntoProtocolsHandler>::Handler,
    ) {
        let (handlers, handler) = handlers.into_inner();
        self.gossipsub
            .inject_connection_closed(peer_id, connection_id, endpoint, handler);
        let (handlers, handler) = handlers.into_inner();
        self.mdns.inject_connection_closed(peer_id, connection_id, endpoint, handler);
        let handler = handlers;
        self.streaming
            .inject_connection_closed(peer_id, connection_id, endpoint, handler);
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        handlers: Self::ProtocolsHandler,
        error: &DialError,
    ) {
        let (handlers, handler) = handlers.into_inner();
        self.gossipsub.inject_dial_failure(peer_id, handler, error);
        let (handlers, handler) = handlers.into_inner();
        self.mdns.inject_dial_failure(peer_id, handler, error);
        let handler = handlers;
        self.streaming.inject_dial_failure(peer_id, handler, error);
    }

    fn inject_listen_failure(
        &mut self,
        local_addr: &Multiaddr,
        send_back_addr: &Multiaddr,
        handlers: Self::ProtocolsHandler,
    ) {
        let (handlers, handler) = handlers.into_inner();
        self.gossipsub.inject_listen_failure(local_addr, send_back_addr, handler);
        let (handlers, handler) = handlers.into_inner();
        self.mdns.inject_listen_failure(local_addr, send_back_addr, handler);
        let handler = handlers;
        self.streaming.inject_listen_failure(local_addr, send_back_addr, handler);
    }

    fn inject_new_listener(&mut self, id: connection::ListenerId) {
        self.streaming.inject_new_listener(id);
        self.mdns.inject_new_listener(id);
        self.gossipsub.inject_new_listener(id);
    }

    fn inject_new_listen_addr(&mut self, id: connection::ListenerId, addr: &Multiaddr) {
        self.streaming.inject_new_listen_addr(id, addr);
        self.mdns.inject_new_listen_addr(id, addr);
        self.gossipsub.inject_new_listen_addr(id, addr);
    }

    fn inject_expired_listen_addr(&mut self, id: connection::ListenerId, addr: &Multiaddr) {
        self.streaming.inject_expired_listen_addr(id, addr);
        self.mdns.inject_expired_listen_addr(id, addr);
        self.gossipsub.inject_expired_listen_addr(id, addr);
    }

    fn inject_new_external_addr(&mut self, addr: &Multiaddr) {
        self.streaming.inject_new_external_addr(addr);
        self.mdns.inject_new_external_addr(addr);
        self.gossipsub.inject_new_external_addr(addr);
    }

    fn inject_expired_external_addr(&mut self, addr: &Multiaddr) {
        self.streaming.inject_expired_external_addr(addr);
        self.mdns.inject_expired_external_addr(addr);
        self.gossipsub.inject_expired_external_addr(addr);
    }

    fn inject_listener_error(
        &mut self,
        id: connection::ListenerId,
        err: &(dyn std::error::Error + 'static),
    ) {
        self.streaming.inject_listener_error(id, err);
        self.mdns.inject_listener_error(id, err);
        self.gossipsub.inject_listener_error(id, err);
    }

    fn inject_listener_closed(
        &mut self,
        id: connection::ListenerId,
        reason: std::result::Result<(), &std::io::Error>,
    ) {
        self.streaming.inject_listener_closed(id, reason);
        self.mdns.inject_listener_closed(id, reason);
        self.gossipsub.inject_listener_closed(id, reason);
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection_id: connection::ConnectionId,
        event: <<Self::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    ) {
        match event {
            either::EitherOutput::First(either::EitherOutput::First(ev)) => {
                NetworkBehaviour::inject_event(&mut self.streaming, peer_id, connection_id, ev)
            }
            either::EitherOutput::First(either::EitherOutput::Second(ev)) => {
                NetworkBehaviour::inject_event(&mut self.mdns, peer_id, connection_id, ev)
            }
            either::EitherOutput::Second(ev) => {
                NetworkBehaviour::inject_event(&mut self.gossipsub, peer_id, connection_id, ev)
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context,
        poll_params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ProtocolsHandler>> {
        match NetworkBehaviour::poll(&mut self.streaming, cx, poll_params) {
            Poll::Ready(NetworkBehaviourAction::GenerateEvent(event)) => {
                return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event.into()))
            }
            Poll::Ready(NetworkBehaviourAction::Dial {
                opts,
                handler: provided_handler,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::Dial {
                    opts,
                    handler: IntoProtocolsHandler::select(
                        IntoProtocolsHandler::select(provided_handler, self.mdns.new_handler()),
                        self.gossipsub.new_handler(),
                    ),
                });
            }
            Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event: either::EitherOutput::First(either::EitherOutput::First(event)),
                });
            }
            Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address, score }) => {
                return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address, score });
            }
            Poll::Ready(NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::CloseConnection {
                    peer_id,
                    connection,
                });
            }
            Poll::Pending => {}
        }

        match NetworkBehaviour::poll(&mut self.mdns, cx, poll_params) {
            Poll::Ready(NetworkBehaviourAction::GenerateEvent(event)) => {
                return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event.into()))
            }
            Poll::Ready(NetworkBehaviourAction::Dial {
                opts,
                handler: provided_handler,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::Dial {
                    opts,
                    handler: IntoProtocolsHandler::select(
                        IntoProtocolsHandler::select(
                            self.streaming.new_handler(),
                            provided_handler,
                        ),
                        self.gossipsub.new_handler(),
                    ),
                });
            }
            Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event: either::EitherOutput::First(either::EitherOutput::Second(event)),
                });
            }
            Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address, score }) => {
                return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address, score });
            }
            Poll::Ready(NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::CloseConnection {
                    peer_id,
                    connection,
                });
            }
            Poll::Pending => {}
        }

        match NetworkBehaviour::poll(&mut self.gossipsub, cx, poll_params) {
            Poll::Ready(NetworkBehaviourAction::GenerateEvent(event)) => {
                return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event.into()))
            }
            Poll::Ready(NetworkBehaviourAction::Dial {
                opts,
                handler: provided_handler,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::Dial {
                    opts,
                    handler: IntoProtocolsHandler::select(
                        IntoProtocolsHandler::select(
                            self.streaming.new_handler(),
                            self.mdns.new_handler(),
                        ),
                        provided_handler,
                    ),
                });
            }
            Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event: either::EitherOutput::Second(event),
                });
            }
            Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address, score }) => {
                return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address, score });
            }
            Poll::Ready(NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::CloseConnection {
                    peer_id,
                    connection,
                });
            }
            Poll::Pending => {}
        }

        let f: Poll<NetworkBehaviourAction<Self::OutEvent, Self::ProtocolsHandler>> = Poll::Pending;
        f
    }
}

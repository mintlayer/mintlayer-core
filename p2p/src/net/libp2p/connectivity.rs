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

//! Connection manager for libp2p
//!
//! `ConnectionManager` handles all connectivity-related activity of the libp2p backend.
//! That includes listening to incoming connections, receiving `IdentifyInfo` events,
//! accepting outbound connections, and handling dial and listening errors.
//!
//! `ConnectionManager` keeps tracks of all active connections in their various different
//! states: connections that are dialed by the local node, inbound connections from remote
//! nodes and connections that are in the process of being closed. When something interesting
//! changes in the connection state, the front-end is informed about it.
//!
//! Outbound connections start in the state `Dialing` and if the connection is rejected, it
//! is removed from the set of active connections and the front-end is informed that the dialing
//! attempt failed. If the connection is accepted, the state is converted to `OutboundAccepted`
//! after which the `ConnectionManager` listens to incoming `IdentifyInfo`. When that is received,
//! the connection state is converted to `Active` and the front-end is notified of the new connection.
//! The process is the same for inbound connections with the exception that they start right away
//! in `InboundAccepted` state and start waiting for the `IdentifyInfo` to be received.

use crate::error::{DialError, P2pError, PeerError};
use libp2p::{
    core::{
        connection::{ConnectedPoint, ConnectionId},
        PeerId,
    },
    identify,
    swarm::{
        handler::DummyConnectionHandler, ConnectionHandler, DialError as Libp2pDialError,
        IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
    },
    Multiaddr,
};
use logging::log;
use std::{
    collections::{HashMap, VecDeque},
    task::{Context, Poll, Waker},
};

/// Events used to command the swarm
pub enum ControlEvent {
    /// Close the connection to peer
    CloseConnection { peer_id: PeerId },
}

/// Events used to report swarm behaviour to front-end
pub enum BehaviourEvent {
    /// Inbound connection accepted
    InboundAccepted {
        addr: Multiaddr,
        peer_info: Box<identify::IdentifyInfo>,
    },

    /// Outbound connection accepted
    OutboundAccepted {
        addr: Multiaddr,
        peer_info: Box<identify::IdentifyInfo>,
    },

    /// Connection closed
    ConnectionClosed { peer_id: PeerId },

    /// Connection error
    ConnectionError { addr: Multiaddr, error: P2pError },
}

/// Events emitted by the `ConnectionManager`
pub enum ConnectionManagerEvent {
    Behaviour(BehaviourEvent),
    Control(ControlEvent),
}

/// State of a pending connection
enum ConnectionState {
    /// Outbound connection has been dialed, wait for `ConnectionEstablished` event
    Dialing,

    /// Connection established for outbound connection
    OutboundAccepted,

    /// Connection established for inbound connection
    InboundAccepted,

    /// Connection is active
    Active,

    /// Connection is in the process of getting closed
    Closing,
}

/// Entry for an established and active connections
struct Connection {
    /// Active address of the remote peer
    addr: Multiaddr,

    /// Connection state of the remote peer
    state: ConnectionState,

    /// `IdentifyInfo` of the remote peer
    peer_info: Option<identify::IdentifyInfo>,
}

impl Connection {
    pub fn new(
        addr: Multiaddr,
        state: ConnectionState,
        peer_info: Option<identify::IdentifyInfo>,
    ) -> Self {
        Self {
            addr,
            state,
            peer_info,
        }
    }

    /// Is the connection still pending (either respose or `IdentifyInfo`)
    pub fn is_pending(&self) -> bool {
        std::matches!(
            self.state,
            ConnectionState::Dialing
                | ConnectionState::OutboundAccepted
                | ConnectionState::InboundAccepted
        )
    }

    /// Is the connection in an active state
    pub fn _is_active(&self) -> bool {
        std::matches!(self.state, ConnectionState::Active)
    }

    /// Is the connection getting closed
    pub fn is_closing(&self) -> bool {
        std::matches!(self.state, ConnectionState::Closing)
    }
}

/// Connection manager
pub struct ConnectionManager {
    /// Handler for waking when a new event is produced
    waker: Option<Waker>,

    /// Set of events polled by the behviour
    events: VecDeque<ConnectionManagerEvent>,

    /// Set of known connections
    connections: HashMap<PeerId, Connection>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            waker: None,
            events: VecDeque::new(),
            connections: HashMap::new(),
        }
    }

    fn add_event(&mut self, event: ConnectionManagerEvent) {
        self.events.push_back(event);

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    /// Close active connection
    pub fn handle_connection_closed(&mut self, peer_id: &PeerId) -> crate::Result<()> {
        if self.connections.remove(peer_id).is_some() {
            self.add_event(ConnectionManagerEvent::Behaviour(
                BehaviourEvent::ConnectionClosed { peer_id: *peer_id },
            ));
            return Ok(());
        }

        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    }

    /// Close the connection to remote peer
    ///
    /// The connection is closed by marking the connection as `Closing` and issuing
    /// a control event `Disconnect` which is captured by the `Swarm` object which
    /// then calls `disconnect_peer_id()`. The resulting event of this operation,
    /// `SwarmEvent::ConnectionClosed` is captured by the `ConnectionManager` which
    /// then informs the front-end about the change in peer state.
    ///
    /// `ConnectionManager` closes the connection only in the most insolent cases
    /// (invalid connection state originating from libp2p) and otherwise it lets
    /// the front-end code to decide when connections should be closed.
    pub fn close_connection(&mut self, peer_id: &PeerId) -> crate::Result<()> {
        if let Some(connection) = self.connections.get_mut(peer_id) {
            if connection.is_closing() {
                return Ok(());
            }

            connection.state = ConnectionState::Closing;
            self.add_event(ConnectionManagerEvent::Control(
                ControlEvent::CloseConnection { peer_id: *peer_id },
            ));
        }

        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    }

    /// Close pending connection
    ///
    /// Something went wrong while the connection was being established. Destroy the entry for the
    /// connection and notify front-end about the peer being possibly malicious.
    fn close_pending_connection(&mut self, peer_id: &PeerId) -> crate::Result<()> {
        if self.connections.remove(peer_id).is_some() {
            self.add_event(ConnectionManagerEvent::Behaviour(
                BehaviourEvent::ConnectionClosed { peer_id: *peer_id },
            ));
            return Ok(());
        }

        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    }

    /// Handle connection refused event
    ///
    /// If the connection is known by connection manager, remove it from the set
    /// of active connections and inform front-end about it.
    fn handle_connection_refused(&mut self, peer_id: &PeerId) -> crate::Result<()> {
        match self.connections.remove(peer_id) {
            Some(connection) => {
                self.add_event(ConnectionManagerEvent::Behaviour(
                    BehaviourEvent::ConnectionError {
                        addr: connection.addr,
                        error: P2pError::DialError(DialError::IoError(
                            std::io::ErrorKind::ConnectionRefused,
                        )),
                    },
                ));
                Ok(())
            }
            None => Err(P2pError::PeerError(PeerError::PeerDoesntExist)),
        }
    }

    /// Handle dial failure
    ///
    /// Check if a connection for `peer_id` exists and if it does, check its state
    /// and based on that either close it as pending or active
    fn handle_dial_failure(&mut self, peer_id: &PeerId) -> crate::Result<()> {
        if let Some(connection) = self.connections.get(peer_id) {
            if connection.is_pending() {
                return self.handle_connection_refused(peer_id);
            }

            // active or closing connections should not emit this event
            return self.close_connection(peer_id);
        }

        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    }

    /// Mark that the peer at `addr` is being dialed, wainting for either
    /// connection establishment or dial error
    pub fn dialing(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if self.connections.get(&peer_id).is_none() {
            self.connections.insert(
                peer_id,
                Connection::new(addr, ConnectionState::Dialing, None),
            );
        }
    }

    // TODO: finish this function
    pub fn register_identify_info(
        &mut self,
        peer_id: &PeerId,
        received_info: identify::IdentifyInfo,
    ) -> crate::Result<()> {
        let mut connection = self
            .connections
            .get_mut(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let event = match connection.state {
            ConnectionState::InboundAccepted => {
                connection.peer_info = Some(received_info.clone());
                connection.state = ConnectionState::Active;

                Some(ConnectionManagerEvent::Behaviour(
                    BehaviourEvent::InboundAccepted {
                        addr: connection.addr.clone(),
                        peer_info: Box::new(received_info),
                    },
                ))
            }
            ConnectionState::OutboundAccepted => {
                connection.peer_info = Some(received_info.clone());
                connection.state = ConnectionState::Active;

                Some(ConnectionManagerEvent::Behaviour(
                    BehaviourEvent::OutboundAccepted {
                        addr: connection.addr.clone(),
                        peer_info: Box::new(received_info),
                    },
                ))
            }
            ConnectionState::Active => None,
            ConnectionState::Closing => None,
            ConnectionState::Dialing => None,
        };

        if let Some(event) = event {
            self.add_event(event);
        }

        Ok(())
    }

    /// Handle connection established event for dialer
    pub fn handle_dialer_connection_established(&mut self, peer_id: &PeerId) -> crate::Result<()> {
        let mut connection = self
            .connections
            .get_mut(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        match connection.state {
            ConnectionState::Dialing => {
                connection.state = ConnectionState::OutboundAccepted;
                Ok(())
            }
            ConnectionState::InboundAccepted | ConnectionState::OutboundAccepted => {
                self.close_pending_connection(peer_id)
            }
            ConnectionState::Active => self.close_connection(peer_id),
            ConnectionState::Closing => Ok(()),
        }
    }

    /// Handle connection established event for listener
    pub fn handle_listener_connection_established(
        &mut self,
        peer_id: &PeerId,
        addr: Multiaddr,
    ) -> crate::Result<()> {
        match self.connections.remove(peer_id) {
            Some(_state) => self.close_connection(peer_id),
            None => {
                self.connections.insert(
                    *peer_id,
                    Connection::new(addr, ConnectionState::InboundAccepted, None),
                );
                Ok(())
            }
        }
    }
}

impl NetworkBehaviour for ConnectionManager {
    type ConnectionHandler = DummyConnectionHandler;
    type OutEvent = ConnectionManagerEvent;

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        self.connections.get(peer_id).map_or(vec![], |connection| {
            connection.peer_info.as_ref().map_or(vec![connection.addr.clone()], |info| {
                info.listen_addrs.clone()
            })
        })
    }

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        DummyConnectionHandler::default()
    }

    fn inject_event(
        &mut self,
        _peer_id: PeerId,
        _connection: ConnectionId,
        _event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
    }

    /// Handle connection established event
    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        _connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
        match endpoint {
            ConnectedPoint::Dialer { .. } => {
                if let Err(err) = self.handle_dialer_connection_established(peer_id) {
                    log::error!(
                        "Connection establishment for peer {} (dialer) failed: {}",
                        peer_id,
                        err
                    );
                }
            }
            ConnectedPoint::Listener { send_back_addr, .. } => {
                if let Err(err) =
                    self.handle_listener_connection_established(peer_id, send_back_addr.clone())
                {
                    log::error!(
                        "Connection establishment for peer {} (listener) failed: {}",
                        peer_id,
                        err
                    );
                }
            }
        }
    }

    /// Handle connection closed event
    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        _connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _event: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        _remaining_established: usize,
    ) {
        if let Err(err) = self.handle_connection_closed(peer_id) {
            log::error!(
                "Connection closed unsuccessfully for peer {}: {}",
                peer_id,
                err
            );
        }
    }

    /// Handle dial failure event
    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        error: &Libp2pDialError,
    ) {
        if let Some(peer_id) = peer_id {
            if let Err(err) = self.handle_dial_failure(&peer_id) {
                if !std::matches!(error, Libp2pDialError::NoAddresses)
                    || err != P2pError::PeerError(PeerError::PeerDoesntExist)
                {
                    log::error!(
                        "Dial error handled unsuccessfully for peer {}: {} {:?}",
                        peer_id,
                        err,
                        error
                    );
                }
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
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

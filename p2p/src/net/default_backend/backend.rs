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

//! Networking backend
//!
//! Every connected peer gets unique ID (generated locally from a counter).

use std::{collections::HashMap, sync::Arc};

use futures::{future::BoxFuture, never::Never, stream::FuturesUnordered, FutureExt};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_stream::{wrappers::ReceiverStream, StreamExt, StreamMap};

use common::{
    chain::ChainConfig,
    primitives::{semver::SemVer, user_agent::UserAgent},
    time_getter::TimeGetter,
};
use logging::log;
use networking::transport::{ConnectedSocketInfo, TransportListener, TransportSocket};
use p2p_types::socket_address::SocketAddress;
use randomness::{make_pseudo_rng, Rng};
use utils::{
    atomics::SeqCstAtomicBool, eventhandler::EventsController, set_flag::SetFlag,
    shallow_clone::ShallowClone,
};

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    error::{DialError, P2pError, PeerError},
    message::PeerManagerMessage,
    net::{
        default_backend::{
            peer,
            types::{BackendEvent, Command, PeerEvent},
        },
        types::{services::Services, ConnectivityEvent, PeerInfo, SyncingEvent},
    },
    protocol::{ProtocolVersion, SupportedProtocolVersion},
    types::{peer_address::PeerAddress, peer_id::PeerId},
    P2pEvent, P2pEventHandler,
};

use super::{
    peer::ConnectionInfo,
    types::{peer_event, HandshakeNonce, Message},
};

/// Buffer sizes for the channels used by Peer to send peer messages to other parts of p2p.
///
/// If the number of unprocessed messages exceeds this limit, the peer's event loop will be
/// blocked; this is needed to prevent DoS attacks where a peer would overload the node with
/// requests, which may lead to memory exhaustion.
/// Note: the values were chosen pretty much arbitrarily; the block sync messages channel has a lower
/// limit because it's used to send blocks, so its messages can be up to 1Mb in size; peer events
/// and transaction-related messages, on the other hand, are small.
/// Also note that basic tests of initial block download time showed that there is no real
/// difference between 20 and 10000 for any of the limits here. These results, of course, depend
/// on the hardware and internet connection, so we've chosen larger limits.
const BLOCK_SYNC_MSG_CHAN_BUF_SIZE: usize = 100;
const TRANSACTION_SYNC_MSG_CHAN_BUF_SIZE: usize = 1000;
const PEER_EVENT_CHAN_BUF_SIZE: usize = 1000;

/// Active peer data
struct PeerContext {
    handle: tokio::task::JoinHandle<()>,

    /// Channel sender for sending messages to the peer's event loop.
    backend_event_sender: mpsc::UnboundedSender<BackendEvent>,

    /// True if the peer was accepted by PeerManager and SyncManager was notified
    was_accepted: SetFlag,

    peer_address: SocketAddress,

    inbound: bool,

    protocol_version: SupportedProtocolVersion,

    user_agent: UserAgent,

    software_version: SemVer,

    /// Intersection of requested (set by us) and available (set by the peer) services.
    /// All services that will be enabled for this peer if it's accepted.
    /// The Peer Manager can disconnect the peer if some required services are missing.
    common_services: Services,
}

/// Pending peer data (until handshake message is received)
struct PendingPeerContext {
    handle: tokio::task::JoinHandle<()>,

    /// Address of the peer.
    peer_address: SocketAddress,

    /// Bind address of this node's side of the connection.
    bind_address: SocketAddress,

    connection_info: ConnectionInfo,

    backend_event_sender: mpsc::UnboundedSender<BackendEvent>,
}

pub struct Backend<T: TransportSocket> {
    /// Whether networking is enabled.
    networking_enabled: bool,

    /// Transport of the backend
    transport: T,

    /// Socket for listening to incoming connections
    socket: T::Listener,

    /// A chain configuration.
    chain_config: Arc<ChainConfig>,

    /// A p2p specific configuration.
    p2p_config: Arc<P2pConfig>,

    time_getter: TimeGetter,

    /// Channel receiver for receiving commands from the frontend
    cmd_receiver: mpsc::UnboundedReceiver<Command>,

    /// Active peers
    peers: HashMap<PeerId, PeerContext>,

    /// Pending connections
    pending_peers: HashMap<PeerId, PendingPeerContext>,

    /// Map of streams for receiving events from peers.
    peer_event_stream_map: StreamMap<PeerId, ReceiverStream<PeerEvent>>,

    /// Channel sender for sending connectivity events to the frontend
    conn_event_sender: mpsc::UnboundedSender<ConnectivityEvent>,

    /// Channel sender for sending syncing events
    syncing_event_sender: mpsc::UnboundedSender<SyncingEvent>,

    /// List of incoming commands to the backend; we put them in a queue
    /// to make sure receiving commands can run concurrently with other backend operations
    command_queue: FuturesUnordered<BackendTask<T>>,

    shutdown: Arc<SeqCstAtomicBool>,
    shutdown_receiver: oneshot::Receiver<()>,

    events_controller: EventsController<P2pEvent>,
    subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,

    /// The protocol version that this node is running. Normally this will be
    /// equal to default_networking_service::PREFERRED_PROTOCOL_VERSION, but it can be
    /// overridden for testing purposes.
    node_protocol_version: ProtocolVersion,
}

impl<T> Backend<T>
where
    T: TransportSocket + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        networking_enabled: bool,
        transport: T,
        socket: T::Listener,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        time_getter: TimeGetter,
        cmd_receiver: mpsc::UnboundedReceiver<Command>,
        conn_event_sender: mpsc::UnboundedSender<ConnectivityEvent>,
        syncing_event_sender: mpsc::UnboundedSender<SyncingEvent>,
        shutdown: Arc<SeqCstAtomicBool>,
        shutdown_receiver: oneshot::Receiver<()>,
        subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
        node_protocol_version: ProtocolVersion,
    ) -> Self {
        Self {
            networking_enabled,
            transport,
            socket,
            cmd_receiver,
            conn_event_sender,
            chain_config,
            p2p_config,
            time_getter,
            syncing_event_sender,
            peers: HashMap::new(),
            pending_peers: HashMap::new(),
            peer_event_stream_map: StreamMap::new(),
            command_queue: FuturesUnordered::new(),
            shutdown,
            shutdown_receiver,
            events_controller: EventsController::new(),
            subscribers_receiver,
            node_protocol_version,
        }
    }

    /// Handle connection result to a remote peer
    fn handle_connect_res(
        &mut self,
        address: SocketAddress,
        local_services_override: Option<Services>,
        connection_res: crate::Result<T::Stream>,
    ) -> crate::Result<()> {
        match connection_res {
            Ok(socket) => {
                let handshake_nonce = make_pseudo_rng().gen();

                self.create_pending_peer(
                    socket,
                    PeerId::new(),
                    ConnectionInfo::Outbound {
                        handshake_nonce,
                        local_services_override,
                    },
                    address,
                )
            }
            Err(err) => {
                // This happens often (for example, if the remote node is behind NAT), so use `info!` here
                log::info!("Failed to establish connection to {address:?}: {err}");

                Ok(
                    self.conn_event_sender.send(ConnectivityEvent::ConnectionError {
                        peer_address: address,
                        error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                    })?,
                )
            }
        }
    }

    /// Allow peer to start reading network messages
    fn accept_peer(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let (block_sync_msg_sender, block_sync_msg_receiver) =
            mpsc::channel(BLOCK_SYNC_MSG_CHAN_BUF_SIZE);
        let (transaction_sync_msg_sender, transaction_sync_msg_receiver) =
            mpsc::channel(TRANSACTION_SYNC_MSG_CHAN_BUF_SIZE);
        peer.backend_event_sender.send(BackendEvent::Accepted {
            block_sync_msg_sender,
            transaction_sync_msg_sender,
        })?;

        let old_value = peer.was_accepted.test_and_set();
        assert!(!old_value);

        Self::send_syncing_event(
            &self.syncing_event_sender,
            SyncingEvent::Connected {
                peer_id,
                common_services: peer.common_services,
                protocol_version: peer.protocol_version,
                block_sync_msg_receiver,
                transaction_sync_msg_receiver,
            },
            &self.shutdown,
        );
        self.events_controller.broadcast(P2pEvent::PeerConnected {
            id: peer_id,
            services: peer.common_services,
            address: peer.peer_address.to_string(),
            inbound: peer.inbound,
            user_agent: peer.user_agent.clone(),
            software_version: peer.software_version,
        });

        Ok(())
    }

    /// Disconnect remote peer by id. Might fail if the peer is already disconnected.
    fn disconnect_peer(
        &mut self,
        peer_id: PeerId,
        reason: Option<DisconnectionReason>,
    ) -> crate::Result<()> {
        // Note: disconnection is performed by sending an event to Peer rather then calling
        // destroy_peer directly, so that Peer has a chance to handle events that have already
        // been sent to it.
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        Ok(peer.backend_event_sender.send(BackendEvent::Disconnect { reason })?)
    }

    /// Sends a message to the remote peer. Might fail if the peer is already disconnected.
    fn send_message(&mut self, peer: PeerId, message: Message) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        Ok(peer.backend_event_sender.send(BackendEvent::SendMessage(Box::new(message)))?)
    }

    /// Runs the backend events loop.
    pub async fn run(mut self) -> crate::Result<Never> {
        loop {
            tokio::select! {
                // Select from the channels in the specified order
                biased;

                // Handle commands.
                command = self.cmd_receiver.recv() => {
                    self.handle_command(command.ok_or(P2pError::ChannelClosed)?);
                },
                // Process pending commands
                Some(callback) = self.command_queue.next() => {
                    callback(&mut self)?;
                },
                // Handle peer events.
                Some((peer_id, event)) = self.peer_event_stream_map.next() => {
                    self.handle_peer_event(peer_id, event)?;
                },
                // Accept a new peer connection.
                res = self.socket.accept() => {
                    match res {
                        Ok((stream, address)) => {
                            if !self.networking_enabled {
                                log::info!("Ignoring incoming connection from {address:?} because networking is disabled");
                            } else {
                                self.create_pending_peer(
                                    stream,
                                    PeerId::new(),
                                    ConnectionInfo::Inbound,
                                    address.into(),
                                )?;
                            }
                        },
                        Err(err) => {
                            // Just log the error and let the node continue working
                            if self.networking_enabled {
                                log::error!("Accepting a new connection failed unexpectedly: {err}")
                            } else {
                                log::debug!(
                                    "Ignoring failed incoming connection because networking is disabled (err = {err})",
                                );
                            }
                        },
                    }
                }
                handler = self.subscribers_receiver.recv() => {
                    self.events_controller.subscribe_to_events(handler.ok_or(P2pError::ChannelClosed)?);
                }
                _ = &mut self.shutdown_receiver => {
                    return Err(P2pError::ChannelClosed);
                }
            }
        }
    }

    /// Create new pending peer
    ///
    /// Move the connection to `pending` where it stays until either the connection is closed
    /// or the handshake message is received at which point the peer information is moved from
    /// `pending` to `peers` and the front-end is notified about the peer.
    fn create_pending_peer(
        &mut self,
        socket: T::Stream,
        peer_id: PeerId,
        connection_info: ConnectionInfo,
        peer_address: SocketAddress,
    ) -> crate::Result<()> {
        let (backend_event_sender, backend_event_receiver) = mpsc::unbounded_channel();

        log::info!("Assigning peer id {peer_id} to peer at address {peer_address:?}");

        let (peer_event_sender, peer_event_receiver) = mpsc::channel(PEER_EVENT_CHAN_BUF_SIZE);
        let peer_event_stream = ReceiverStream::new(peer_event_receiver);
        let bind_address = socket.local_address()?;

        self.peer_event_stream_map.insert(peer_id, peer_event_stream);

        let peer = peer::Peer::<T>::new(
            peer_id,
            connection_info,
            self.chain_config.shallow_clone(),
            self.p2p_config.shallow_clone(),
            socket,
            peer_event_sender,
            backend_event_receiver,
            self.node_protocol_version,
            self.time_getter.shallow_clone(),
        );
        let shutdown = Arc::clone(&self.shutdown);
        let handle = logging::spawn_in_current_span(async move {
            match peer.run().await {
                Ok(()) => {}
                Err(P2pError::ChannelClosed) if shutdown.load() => {}
                Err(e) => log::error!("Peer {peer_id} failed: {e}"),
            }
        });

        self.pending_peers.insert(
            peer_id,
            PendingPeerContext {
                handle,
                peer_address,
                bind_address: bind_address.into(),
                connection_info,
                backend_event_sender,
            },
        );

        Ok(())
    }

    /// Create new peer after handshake.
    ///
    /// Try to create a new peer after receiving a handshake.
    fn create_peer(
        &mut self,
        peer_id: PeerId,
        handshake_nonce: HandshakeNonce,
        peer_info: PeerInfo,
        node_address_as_seen_by_peer: Option<PeerAddress>,
    ) -> crate::Result<()> {
        let PendingPeerContext {
            handle,
            peer_address,
            bind_address,
            connection_info,
            backend_event_sender,
        } = match self.pending_peers.remove(&peer_id) {
            Some(pending_peer) => pending_peer,
            // Could be removed if self-connection was detected earlier
            None => return Ok(()),
        };

        log::debug!("Creating peer {peer_id} after handshake");

        if self.is_connection_from_self(connection_info, handshake_nonce)? {
            log::debug!("Peer {peer_id} is a connection from self");

            // Note: backend_event_sender will be dropped immediately after this; but the receiver
            // part will still produce messages that were in flight when the sender was dropped,
            // so Peer will be able to receive this event.
            backend_event_sender.send(BackendEvent::Disconnect {
                reason: Some(DisconnectionReason::ConnectionFromSelf),
            })?;
            return Ok(());
        }

        let common_services = peer_info.common_services;
        let protocol_version = peer_info.protocol_version;
        let inbound = connection_info == ConnectionInfo::Inbound;
        let user_agent = peer_info.user_agent.clone();
        let software_version = peer_info.software_version;

        match connection_info {
            ConnectionInfo::Outbound {
                handshake_nonce: _,
                local_services_override: _,
            } => {
                self.conn_event_sender.send(ConnectivityEvent::OutboundAccepted {
                    peer_address,
                    bind_address,
                    peer_info,
                    node_address_as_seen_by_peer,
                })?;
            }
            ConnectionInfo::Inbound => {
                self.conn_event_sender.send(ConnectivityEvent::InboundAccepted {
                    peer_address,
                    bind_address,
                    peer_info,
                    node_address_as_seen_by_peer,
                })?;
            }
        }

        self.peers.insert(
            peer_id,
            PeerContext {
                handle,
                peer_address,
                inbound,
                protocol_version,
                user_agent,
                software_version,
                common_services,
                backend_event_sender,
                was_accepted: SetFlag::new(),
            },
        );

        Ok(())
    }

    /// Destroy peer.
    ///
    /// Peer should not be in pending state.
    fn destroy_peer(&mut self, peer_id: PeerId) -> crate::Result<()> {
        // Make sure the peer exists so that `ConnectionClosed` is sent only once
        let peer = self
            .peers
            .remove(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        if peer.was_accepted.test() {
            Self::send_syncing_event(
                &self.syncing_event_sender,
                SyncingEvent::Disconnected { peer_id },
                &self.shutdown,
            );
            self.events_controller.broadcast(P2pEvent::PeerDisconnected(peer_id));
        }

        // Terminate the peer's event loop as soon as possible.
        // It's needed to free used resources if the peer is blocked at some await point
        // (for example, trying to send something big over a slow network connection)
        peer.handle.abort();

        Ok(self.conn_event_sender.send(ConnectivityEvent::ConnectionClosed { peer_id })?)
    }

    fn is_connection_from_self(
        &mut self,
        connection_info: ConnectionInfo,
        incoming_nonce: HandshakeNonce,
    ) -> crate::Result<bool> {
        if connection_info == ConnectionInfo::Inbound {
            // Look for own outbound connection with same nonce
            let pending_outbound_peer_id = self
                .pending_peers
                .iter()
                .find(|(_peer_id, peer_ctx)| match peer_ctx.connection_info {
                    ConnectionInfo::Inbound => false,
                    ConnectionInfo::Outbound {
                        handshake_nonce,
                        local_services_override: _,
                    } => handshake_nonce == incoming_nonce,
                })
                .map(|(peer_id, _pending)| *peer_id);

            if let Some(peer_id) = pending_outbound_peer_id {
                let peer_ctx = self.pending_peers.remove(&peer_id).expect("peer must exist");

                log::info!(
                    "self-connection detected on address {:?}",
                    peer_ctx.peer_address
                );

                // Report outbound connection failure
                self.conn_event_sender.send(ConnectivityEvent::ConnectionError {
                    peer_address: peer_ctx.peer_address,
                    error: P2pError::DialError(DialError::AttemptToDialSelf),
                })?;

                // Nothing else to do, just drop inbound connection
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn handle_peer_event(&mut self, peer_id: PeerId, event: PeerEvent) -> crate::Result<()> {
        if !self.networking_enabled {
            log::debug!("Got an event from peer {peer_id} while networking is disabled: {event:?}");
        }

        match event {
            PeerEvent::PeerInfoReceived(peer_event::PeerInfo {
                protocol_version,
                network,
                common_services,
                user_agent,
                software_version,
                node_address_as_seen_by_peer,
                handshake_nonce,
            }) => {
                if self.networking_enabled {
                    self.create_peer(
                        peer_id,
                        handshake_nonce,
                        PeerInfo {
                            peer_id,
                            protocol_version,
                            network,
                            software_version,
                            user_agent,
                            common_services,
                        },
                        node_address_as_seen_by_peer,
                    )?;
                }

                Ok(())
            }

            PeerEvent::MessageReceived { message } => {
                if self.networking_enabled {
                    self.handle_message(peer_id, message)?;
                }

                Ok(())
            }

            PeerEvent::MisbehavedOnHandshake { error } => {
                if let Some(pending_peer) = self.pending_peers.get(&peer_id) {
                    log::debug!(
                        "Sending ConnectivityEvent::MisbehavedOnHandshake for peer {peer_id}"
                    );

                    self.conn_event_sender.send(ConnectivityEvent::MisbehavedOnHandshake {
                        peer_address: pending_peer.peer_address,
                        error,
                    })?;
                } else {
                    log::error!("Cannot find pending peer for peer id {peer_id}");
                }

                Ok(())
            }

            PeerEvent::ConnectionClosed => {
                if let Some(pending_peer) = self.pending_peers.remove(&peer_id) {
                    // Note: we'll get here if handshake has failed, so no need to use log levels
                    // higher that debug, because the error should have been logged properly already.
                    match pending_peer.connection_info {
                        ConnectionInfo::Inbound => {
                            log::debug!(
                                "Inbound pending connection from {} was closed",
                                pending_peer.peer_address
                            );
                        }
                        ConnectionInfo::Outbound {
                            handshake_nonce: _,
                            local_services_override: _,
                        } => {
                            log::debug!(
                                "Outbound pending connection to {} was closed",
                                pending_peer.peer_address
                            );

                            // TODO: this ConnectionRefusedOrTimedOut is misleading; probably
                            // we should include the actual error in PeerEvent::ConnectionClosed
                            // and propagate it here.
                            self.conn_event_sender.send(ConnectivityEvent::ConnectionError {
                                peer_address: pending_peer.peer_address,
                                error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                            })?;
                        }
                    }
                }

                // If the peer was previously disconnected by us, the `peers' will be empty.
                // `ConnectionClosed` should be ignored in such case.
                if self.peers.contains_key(&peer_id) {
                    self.destroy_peer(peer_id)?;
                }

                Ok(())
            }

            PeerEvent::Misbehaved { error } => {
                self.conn_event_sender.send(ConnectivityEvent::Misbehaved { peer_id, error })?;

                Ok(())
            }

            PeerEvent::Sync {
                event_received_confirmation_sender,
            } => {
                let _ = event_received_confirmation_sender.send(());
                Ok(())
            }
        }
    }

    fn handle_message(
        &mut self,
        peer_id: PeerId,
        message: PeerManagerMessage,
    ) -> crate::Result<()> {
        // Do not process remaining messages if the peer has been forcibly disconnected (for example, after being banned).
        // Without this check, the backend might send messages to the sync and peer managers after sending the disconnect notification.
        if !self.peers.contains_key(&peer_id) {
            log::info!("ignore received messaged from a disconnected peer {peer_id}");
            return Ok(());
        }

        self.conn_event_sender.send(ConnectivityEvent::Message { peer_id, message })?;

        Ok(())
    }

    fn handle_command(&mut self, command: Command) {
        // All handlings can be separated to two parts:
        // - Async (can't take mutable reference to self because they are run concurrently).
        // - Sync (take mutable reference to self because they are run sequentially).
        // Because the second part depends on result of the first part boxed closures are used.

        match command {
            Command::Connect {
                address,
                local_services_override,
            } => {
                let connection_fut = timeout(
                    *self.p2p_config.outbound_connection_timeout,
                    self.transport.connect(address.socket_addr()),
                );

                let backend_task: BackendTask<T> = async move {
                    let connection_res = match connection_fut.await {
                        Err(_) => Err(P2pError::DialError(DialError::ConnectionRefusedOrTimedOut)),
                        Ok(networking_result) => {
                            networking_result.map_err(P2pError::NetworkingError)
                        }
                    };

                    boxed_cb(move |this| {
                        this.handle_connect_res(address, local_services_override, connection_res)
                    })
                }
                .boxed();

                self.command_queue.push(backend_task);
            }
            Command::Accept { peer_id } => {
                let res = self.accept_peer(peer_id);
                if let Err(e) = res {
                    log::debug!("Failed to accept peer {peer_id}: {e}");
                }
            }
            Command::Disconnect { peer_id, reason } => {
                let res = self.disconnect_peer(peer_id, reason);
                if let Err(e) = res {
                    log::debug!("Failed to disconnect peer {peer_id}: {e}");
                }
            }
            Command::SendMessage { peer_id, message } => {
                let res = self.send_message(peer_id, message);
                if let Err(e) = res {
                    log::debug!("Failed to send request to peer {peer_id}: {e}")
                }
            }
            Command::EnableNetworking { enable } => {
                if self.networking_enabled != enable {
                    self.networking_enabled = enable;

                    if !self.networking_enabled {
                        for backend_event_sender in
                            self.peers.values().map(|peer| &peer.backend_event_sender).chain(
                                self.pending_peers.values().map(|peer| &peer.backend_event_sender),
                            )
                        {
                            let _ = backend_event_sender.send(BackendEvent::Disconnect {
                                reason: Some(DisconnectionReason::NetworkingDisabled),
                            });
                        }
                    }
                }
            }
        };
    }

    fn send_syncing_event(
        event_sender: &mpsc::UnboundedSender<SyncingEvent>,
        event: SyncingEvent,
        shutdown: &Arc<SeqCstAtomicBool>,
    ) {
        // NOTE: `event_sender` is not connected in some PeerManager tests.
        match event_sender.send(event) {
            Ok(()) => {}
            Err(_) if shutdown.load() => {}
            Err(_) => log::error!("sending syncing event from the backend failed unexpectedly"),
        }
    }
}

// Some boilerplate types and a function for blocking tasks handling

type BackendTask<T> = BoxFuture<'static, BackendTaskCallback<T>>;

type BackendTaskCallback<T> = Box<dyn FnOnce(&mut Backend<T>) -> crate::Result<()> + Send>;

fn boxed_cb<
    T: TransportSocket,
    F: FnOnce(&mut Backend<T>) -> crate::Result<()> + Send + 'static,
>(
    f: F,
) -> BackendTaskCallback<T> {
    Box::new(f)
}

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

use futures::{future::BoxFuture, never::Never, stream::FuturesUnordered, FutureExt, StreamExt};
use p2p_types::socket_address::SocketAddress;
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};
use tracing::Instrument;

use common::{
    chain::ChainConfig,
    primitives::{semver::SemVer, user_agent::UserAgent},
    time_getter::TimeGetter,
};
use crypto::random::{make_pseudo_rng, Rng};
use logging::log;
use utils::{atomics::SeqCstAtomicBool, eventhandler::EventsController, set_flag::SetFlag};

use crate::{
    config::P2pConfig,
    error::{DialError, P2pError, PeerError},
    message::PeerManagerMessage,
    net::{
        default_backend::{
            peer,
            transport::{TransportListener, TransportSocket},
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
    types::{HandshakeNonce, Message, P2pTimestamp},
};

/// Buffer size of the channel to the SyncManager peer task.
/// How many unprocessed messages can be sent before the peer's event loop is blocked.
// TODO: Decide what the optimal value is (for example, by comparing the initial block download time)
const SYNC_CHAN_BUF_SIZE: usize = 20;

/// Active peer data
struct PeerContext {
    handle: tokio::task::JoinHandle<()>,

    /// Channel sender for sending messages to the peer's event loop.
    backend_event_tx: mpsc::UnboundedSender<BackendEvent>,

    /// True if the peer was accepted by PeerManager and SyncManager was notified
    was_accepted: SetFlag,

    address: SocketAddress,

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

    address: SocketAddress,

    connection_info: ConnectionInfo,

    backend_event_tx: mpsc::UnboundedSender<BackendEvent>,
}

pub struct Backend<T: TransportSocket> {
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
    cmd_rx: mpsc::UnboundedReceiver<Command>,

    /// Active peers
    peers: HashMap<PeerId, PeerContext>,

    /// Pending connections
    pending: HashMap<PeerId, PendingPeerContext>,

    /// Channel sender for sending events from Peers to Backend; this will be passed to each
    /// Peer upon its creation.
    peer_event_tx: mpsc::UnboundedSender<(PeerId, PeerEvent)>,

    /// Channel receiver for receiving events from Peers
    peer_event_rx: mpsc::UnboundedReceiver<(PeerId, PeerEvent)>,

    /// Channel sender for sending connectivity events to the frontend
    conn_event_tx: mpsc::UnboundedSender<ConnectivityEvent>,

    /// Channel sender for sending syncing events
    syncing_event_tx: mpsc::UnboundedSender<SyncingEvent>,

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
        transport: T,
        socket: T::Listener,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        time_getter: TimeGetter,
        cmd_rx: mpsc::UnboundedReceiver<Command>,
        conn_event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
        syncing_event_tx: mpsc::UnboundedSender<SyncingEvent>,
        shutdown: Arc<SeqCstAtomicBool>,
        shutdown_receiver: oneshot::Receiver<()>,
        subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
        node_protocol_version: ProtocolVersion,
    ) -> Self {
        let (peer_event_tx, peer_event_rx) = mpsc::unbounded_channel();
        Self {
            transport,
            socket,
            cmd_rx,
            conn_event_tx,
            chain_config,
            p2p_config,
            time_getter,
            syncing_event_tx,
            peers: HashMap::new(),
            pending: HashMap::new(),
            peer_event_tx,
            peer_event_rx,
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

                Ok(self.conn_event_tx.send(ConnectivityEvent::ConnectionError {
                    address,
                    error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                })?)
            }
        }
    }

    /// Allow peer to start reading network messages
    fn accept_peer(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let (sync_msg_tx, sync_msg_rx) = mpsc::channel(SYNC_CHAN_BUF_SIZE);
        peer.backend_event_tx.send(BackendEvent::Accepted { sync_msg_tx })?;

        let old_value = peer.was_accepted.test_and_set();
        assert!(!old_value);

        Self::send_syncing_event(
            &self.syncing_event_tx,
            SyncingEvent::Connected {
                peer_id,
                common_services: peer.common_services,
                protocol_version: peer.protocol_version,
                sync_msg_rx,
            },
            &self.shutdown,
        );
        self.events_controller.broadcast(P2pEvent::PeerConnected {
            id: peer_id,
            services: peer.common_services,
            address: peer.address.to_string(),
            inbound: peer.inbound,
            user_agent: peer.user_agent.clone(),
            software_version: peer.software_version,
        });

        Ok(())
    }

    /// Disconnect remote peer by id. Might fail if the peer is already disconnected.
    fn disconnect_peer(&mut self, peer_id: PeerId) -> crate::Result<()> {
        self.peers
            .get(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        self.destroy_peer(peer_id)
    }

    /// Sends a message to the remote peer. Might fail if the peer is already disconnected.
    fn send_message(&mut self, peer: PeerId, message: Message) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        Ok(peer.backend_event_tx.send(BackendEvent::SendMessage(Box::new(message)))?)
    }

    /// Runs the backend events loop.
    pub async fn run(mut self) -> crate::Result<Never> {
        loop {
            tokio::select! {
                // Select from the channels in the specified order
                biased;

                // Handle commands.
                command = self.cmd_rx.recv() => {
                    self.handle_command(command.ok_or(P2pError::ChannelClosed)?);
                },
                // Process pending commands
                callback = self.command_queue.select_next_some(), if !self.command_queue.is_empty() => {
                    callback(&mut self)?;
                },
                // Handle peer events.
                event = self.peer_event_rx.recv() => {
                    let (peer, event) = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_peer_event(peer, event)?;
                },
                // Accept a new peer connection.
                res = self.socket.accept() => {
                    match res {
                        Ok((stream, address)) => {
                            self.create_pending_peer(
                                stream,
                                PeerId::new(),
                                ConnectionInfo::Inbound,
                                address,
                            )?;
                        },
                        Err(err) => {
                            // Just log the error and let the node continue working
                            log::error!("Accepting a new connection failed unexpectedly: {err}")
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
        remote_peer_id: PeerId,
        connection_info: ConnectionInfo,
        address: SocketAddress,
    ) -> crate::Result<()> {
        let (backend_event_tx, backend_event_rx) = mpsc::unbounded_channel();

        log::debug!("Assigning peer id {remote_peer_id} to peer at address {address:?}");

        // Sending the remote socket address makes no sense and can leak private information when using a proxy
        let receiver_address = if self.p2p_config.socks5_proxy.is_some() {
            None
        } else {
            Some(address.as_peer_address())
        };

        let peer_event_tx = self.peer_event_tx.clone();

        let peer = peer::Peer::<T>::new(
            remote_peer_id,
            connection_info,
            Arc::clone(&self.chain_config),
            Arc::clone(&self.p2p_config),
            socket,
            receiver_address,
            peer_event_tx,
            backend_event_rx,
            self.node_protocol_version,
        );
        let shutdown = Arc::clone(&self.shutdown);
        let local_time = P2pTimestamp::from_duration_since_epoch(self.time_getter.get_time());
        let handle = tokio::spawn(
            async move {
                match peer.run(local_time).await {
                    Ok(()) => {}
                    Err(P2pError::ChannelClosed) if shutdown.load() => {}
                    Err(e) => log::error!("peer {remote_peer_id} failed: {e}"),
                }
            }
            .instrument(tracing::Span::current()),
        );

        self.pending.insert(
            remote_peer_id,
            PendingPeerContext {
                handle,
                address,
                connection_info,
                backend_event_tx,
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
        receiver_address: Option<PeerAddress>,
    ) -> crate::Result<()> {
        let PendingPeerContext {
            handle,
            address,
            connection_info,
            backend_event_tx,
        } = match self.pending.remove(&peer_id) {
            Some(pending) => pending,
            // Could be removed if self-connection was detected earlier
            None => return Ok(()),
        };

        if self.is_connection_from_self(connection_info, handshake_nonce)? {
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
                self.conn_event_tx.send(ConnectivityEvent::OutboundAccepted {
                    address,
                    peer_info,
                    receiver_address,
                })?;
            }
            ConnectionInfo::Inbound => {
                self.conn_event_tx.send(ConnectivityEvent::InboundAccepted {
                    address,
                    peer_info,
                    receiver_address,
                })?;
            }
        }

        self.peers.insert(
            peer_id,
            PeerContext {
                handle,
                address,
                inbound,
                protocol_version,
                user_agent,
                software_version,
                common_services,
                backend_event_tx,
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
                &self.syncing_event_tx,
                SyncingEvent::Disconnected { peer_id },
                &self.shutdown,
            );
            self.events_controller.broadcast(P2pEvent::PeerDisconnected(peer_id));
        }

        // Terminate the peer's event loop as soon as possible.
        // It's needed to free used resources if the peer is blocked at some await point
        // (for example, trying to send something big over a slow network connection)
        peer.handle.abort();

        Ok(self.conn_event_tx.send(ConnectivityEvent::ConnectionClosed { peer_id })?)
    }

    fn is_connection_from_self(
        &mut self,
        connection_info: ConnectionInfo,
        incoming_nonce: HandshakeNonce,
    ) -> crate::Result<bool> {
        if connection_info == ConnectionInfo::Inbound {
            // Look for own outbound connection with same nonce
            let outbound_peer_id = self
                .pending
                .iter()
                .find(|(_peer_id, pending)| match pending.connection_info {
                    ConnectionInfo::Inbound => false,
                    ConnectionInfo::Outbound {
                        handshake_nonce,
                        local_services_override: _,
                    } => handshake_nonce == incoming_nonce,
                })
                .map(|(peer_id, _pending)| *peer_id);

            if let Some(outbound_peer_id) = outbound_peer_id {
                let outbound_pending =
                    self.pending.remove(&outbound_peer_id).expect("peer must exist");

                log::info!(
                    "self-connection detected on address {:?}",
                    outbound_pending.address
                );

                // Report outbound connection failure
                self.conn_event_tx.send(ConnectivityEvent::ConnectionError {
                    address: outbound_pending.address,
                    error: P2pError::DialError(DialError::AttemptToDialSelf),
                })?;

                // Nothing else to do, just drop inbound connection
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn handle_peer_event(&mut self, peer_id: PeerId, event: PeerEvent) -> crate::Result<()> {
        match event {
            PeerEvent::PeerInfoReceived {
                protocol_version,
                network,
                common_services,
                user_agent,
                software_version,
                receiver_address,
                handshake_nonce,
            } => self.create_peer(
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
                receiver_address,
            ),

            PeerEvent::MessageReceived { message } => self.handle_message(peer_id, message),

            PeerEvent::HandshakeFailed { error } => {
                if let Some(pending_peer) = self.pending.get(&peer_id) {
                    log::debug!("Sending ConnectivityEvent::HandshakeFailed for peer {peer_id}");

                    let send_result = self.conn_event_tx.send(ConnectivityEvent::HandshakeFailed {
                        address: pending_peer.address,
                        error,
                    });
                    if let Err(send_error) = send_result {
                        log::error!(
                            "Unable to report a failed handshake for peer {} to the front end: {}",
                            peer_id,
                            send_error
                        );
                    }
                } else {
                    log::error!("Cannot find pending peer for peer id {peer_id}");
                }

                Ok(())
            }

            PeerEvent::ConnectionClosed => {
                if let Some(pending_peer) = self.pending.remove(&peer_id) {
                    match pending_peer.connection_info {
                        ConnectionInfo::Inbound => {
                            // Just log the error
                            log::warn!("inbound pending connection closed unexpectedly");
                        }
                        ConnectionInfo::Outbound {
                            handshake_nonce: _,
                            local_services_override: _,
                        } => {
                            log::warn!("outbound pending connection closed unexpectedly");

                            self.conn_event_tx.send(ConnectivityEvent::ConnectionError {
                                address: pending_peer.address,
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

        self.conn_event_tx.send(ConnectivityEvent::Message { peer_id, message })?;

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
                    self.transport.connect(address),
                );

                let backend_task: BackendTask<T> = async move {
                    let connection_res = connection_fut.await.unwrap_or(Err(P2pError::DialError(
                        DialError::ConnectionRefusedOrTimedOut,
                    )));

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
            Command::Disconnect { peer_id } => {
                let res = self.disconnect_peer(peer_id);
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
        };
    }

    fn send_syncing_event(
        event_tx: &mpsc::UnboundedSender<SyncingEvent>,
        event: SyncingEvent,
        shutdown: &Arc<SeqCstAtomicBool>,
    ) {
        // SyncManager should always be active and so sending to a closed `conn_tx` is not a backend's problem, just log the error.
        // NOTE: `sync_tx` is not connected in some PeerManager tests.
        match event_tx.send(event) {
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

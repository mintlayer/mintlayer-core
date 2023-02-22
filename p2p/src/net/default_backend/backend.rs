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

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use tokio::{sync::mpsc, time::timeout};

use common::chain::ChainConfig;
use crypto::random::{make_pseudo_rng, Rng, SliceRandom};
use logging::log;
use serialization::{Decode, Encode};

use crate::{
    config::P2pConfig,
    error::{DialError, P2pError, PeerError, PublishError},
    message::{PeerManagerMessage, SyncMessage},
    net::{
        default_backend::{
            constants::ANNOUNCEMENT_MAX_SIZE,
            peer,
            transport::{TransportListener, TransportSocket},
            types::{Command, Event, Message, PeerEvent},
        },
        types::{ConnectivityEvent, PeerInfo, PubSubTopic, SyncingEvent},
        Announcement,
    },
    types::{peer_address::PeerAddress, peer_id::PeerId},
};

use super::{peer::PeerRole, transport::TransportAddress, types::HandshakeNonce};

/// Active peer data
struct PeerContext {
    subscriptions: BTreeSet<PubSubTopic>,

    /// Channel used to send messages to the peer's event loop.
    ///
    /// Note that sending may fail unexpectedly if the connection is closed!
    /// Do not propagate ChannelClosed error to the higher level, handle it locally!
    tx: mpsc::UnboundedSender<Event>,
}

/// Pending peer data (until handshake message is received)
struct PendingPeerContext<A> {
    address: A,

    peer_role: PeerRole,

    tx: mpsc::UnboundedSender<Event>,
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

    /// RX channel for receiving commands from the frontend
    cmd_rx: mpsc::UnboundedReceiver<Command<T::Address>>,

    /// Active peers
    peers: HashMap<PeerId, PeerContext>,

    /// Pending connections
    pending: HashMap<PeerId, PendingPeerContext<T::Address>>,

    /// RX channel for receiving events from peers
    #[allow(clippy::type_complexity)]
    peer_chan: (
        mpsc::UnboundedSender<(PeerId, PeerEvent)>,
        mpsc::UnboundedReceiver<(PeerId, PeerEvent)>,
    ),

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::UnboundedSender<ConnectivityEvent<T::Address>>,

    /// TX channel for sending syncing events
    sync_tx: mpsc::UnboundedSender<SyncingEvent>,

    /// List of incoming commands to the backend; we put them in a queue
    /// to make receiving commands can run concurrently with other backend operations
    command_queue: FuturesUnordered<BackendTask<T>>,
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
        cmd_rx: mpsc::UnboundedReceiver<Command<T::Address>>,
        conn_tx: mpsc::UnboundedSender<ConnectivityEvent<T::Address>>,
        sync_tx: mpsc::UnboundedSender<SyncingEvent>,
    ) -> Self {
        Self {
            transport,
            socket,
            cmd_rx,
            conn_tx,
            chain_config,
            p2p_config,
            sync_tx,
            peers: HashMap::new(),
            pending: HashMap::new(),
            peer_chan: mpsc::unbounded_channel(),
            command_queue: FuturesUnordered::new(),
        }
    }

    /// Handle connection result to a remote peer
    fn handle_connect_res(
        &mut self,
        address: T::Address,
        connection_res: crate::Result<T::Stream>,
    ) -> crate::Result<()> {
        match connection_res {
            Ok(socket) => {
                let handshake_nonce = make_pseudo_rng().gen();

                self.create_pending_peer(
                    socket,
                    PeerId::new(),
                    PeerRole::Outbound { handshake_nonce },
                    address,
                )
            }
            Err(err) => {
                log::error!("Failed to establish connection: {err}");

                self.conn_tx
                    .send(ConnectivityEvent::ConnectionError {
                        address,
                        error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                    })
                    .map_err(P2pError::from)
            }
        }
    }

    /// Disconnect remote peer by id. Might fail if the peer is already disconnected.
    fn disconnect_peer(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let peer = self
            .peers
            .get(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        peer.tx.send(Event::Disconnect).map_err(P2pError::from)?;

        self.destroy_peer(peer_id)
    }

    /// Sends a message the remote peer. Might fail if the peer is already disconnected.
    fn send_message(&mut self, peer: PeerId, message: Message) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        peer.tx.send(Event::SendMessage(Box::new(message))).map_err(P2pError::from)
    }

    /// Sends the announcement to all peers.
    ///
    /// It is not an error if there are no peers that subscribed to the related topic.
    fn announce_data(&mut self, topic: PubSubTopic, message: Vec<u8>) -> crate::Result<()> {
        let announcement = Announcement::decode(&mut &message[..])?;

        // Send the message to peers in pseudorandom order.
        let mut peers: Vec<_> = self
            .peers
            .iter()
            .filter(|(_peer_id, peer)| peer.subscriptions.contains(&topic))
            .collect();
        peers.shuffle(&mut make_pseudo_rng());

        for (peer_id, peer) in peers {
            let res = peer.tx.send(Event::SendMessage(Box::new(Message::Announcement(
                Box::new(announcement.clone()),
            ))));
            if let Err(e) = res {
                log::error!("Failed to send announcement to peer {peer_id}: {e:?}")
            }
        }

        Ok(())
    }

    fn handle_announcement(
        &mut self,
        peer_id: PeerId,
        announcement: Announcement,
    ) -> crate::Result<()> {
        let size = announcement.encode().len();
        if size > ANNOUNCEMENT_MAX_SIZE {
            self.conn_tx
                .send(ConnectivityEvent::Misbehaved {
                    peer_id,
                    error: P2pError::PublishError(PublishError::MessageTooLarge(
                        size,
                        ANNOUNCEMENT_MAX_SIZE,
                    )),
                })
                .map_err(P2pError::from)?;
        }

        self.sync_tx
            .send(SyncingEvent::Announcement {
                peer: peer_id,
                announcement: Box::new(announcement),
            })
            .map_err(P2pError::from)
    }

    /// Runs the backend events loop.
    pub async fn run(&mut self) -> crate::Result<()> {
        loop {
            tokio::select! {
                // Select from the channels in the specified order
                biased;

                // Handle commands.
                command = self.cmd_rx.recv() => {
                    self.handle_command(command.ok_or(P2pError::ChannelClosed)?).await?;
                },
                // Process pending commands
                callback = self.command_queue.select_next_some(), if !self.command_queue.is_empty() => {
                    callback(self)?;
                },
                // Handle peer events.
                event = self.peer_chan.1.recv() => {
                    let (peer, event) = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_peer_event(peer, event)?;
                },
                // Accept a new peer connection.
                res = self.socket.accept() => {
                    let (stream, address) = res.map_err(|_| P2pError::DialError(DialError::AcceptFailed))?;

                    self.create_pending_peer(
                        stream,
                        PeerId::new(),
                        PeerRole::Inbound,
                        address,
                    )?;
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
        peer_role: PeerRole,
        address: T::Address,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::unbounded_channel();

        let receiver_address = Some(address.as_peer_address());

        self.pending.insert(
            remote_peer_id,
            PendingPeerContext {
                address,
                peer_role,
                tx,
            },
        );

        let tx = self.peer_chan.0.clone();
        let chain_config = Arc::clone(&self.chain_config);
        let p2p_config = Arc::clone(&self.p2p_config);

        tokio::spawn(async move {
            let mut peer = peer::Peer::<T>::new(
                remote_peer_id,
                peer_role,
                chain_config,
                p2p_config,
                socket,
                receiver_address,
                tx,
                rx,
            );
            let run_res = peer.run().await;
            if let Err(err) = run_res {
                log::error!("peer {remote_peer_id} failed: {err}");
            }
        });

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
            address,
            peer_role,
            tx,
        } = match self.pending.remove(&peer_id) {
            Some(pending) => pending,
            // Could be removed if self-connection was detected earlier
            None => return Ok(()),
        };

        if self.is_connection_from_self(peer_role, handshake_nonce)? {
            return Ok(());
        }

        let subscriptions = peer_info.subscriptions.clone();

        match peer_role {
            PeerRole::Outbound { handshake_nonce: _ } => {
                self.conn_tx
                    .send(ConnectivityEvent::OutboundAccepted {
                        address,
                        peer_info,
                        receiver_address,
                    })
                    .map_err(P2pError::from)?;
            }
            PeerRole::Inbound => {
                self.conn_tx
                    .send(ConnectivityEvent::InboundAccepted {
                        address,
                        peer_info,
                        receiver_address,
                    })
                    .map_err(P2pError::from)?;
            }
        }

        self.peers.insert(peer_id, PeerContext { subscriptions, tx });

        Ok(())
    }

    /// Destroy peer.
    ///
    /// Peer should not be in pending state.
    fn destroy_peer(&mut self, peer_id: PeerId) -> crate::Result<()> {
        // Make sure the peer exists so that `ConnectionClosed` is sent only once
        self.peers
            .remove(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        self.conn_tx
            .send(ConnectivityEvent::ConnectionClosed { peer_id })
            .map_err(P2pError::from)
    }

    fn is_connection_from_self(
        &mut self,
        peer_role: PeerRole,
        incoming_nonce: HandshakeNonce,
    ) -> crate::Result<bool> {
        if peer_role == PeerRole::Inbound {
            // Look for own outbound connection with same nonce
            let outbound_peer_id = self
                .pending
                .iter()
                .find(|(_peer_id, pending)| {
                    pending.peer_role
                        == PeerRole::Outbound {
                            handshake_nonce: incoming_nonce,
                        }
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
                self.conn_tx
                    .send(ConnectivityEvent::ConnectionError {
                        address: outbound_pending.address,
                        error: P2pError::DialError(DialError::AttemptToDialSelf),
                    })
                    .map_err(P2pError::from)?;

                // Nothing else to do, just drop inbound connection
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn handle_peer_event(&mut self, peer_id: PeerId, event: PeerEvent) -> crate::Result<()> {
        match event {
            PeerEvent::PeerInfoReceived {
                network,
                version,
                subscriptions,
                receiver_address,
                handshake_nonce,
            } => self.create_peer(
                peer_id,
                handshake_nonce,
                PeerInfo {
                    peer_id,
                    network,
                    version,
                    agent: None,
                    subscriptions,
                },
                receiver_address,
            ),

            PeerEvent::MessageReceived { message } => self.handle_message(peer_id, message),

            PeerEvent::ConnectionClosed => {
                self.pending.remove(&peer_id);

                // If the peer was previously disconnected by us, the `peers' will be empty.
                // `ConnectionClosed` should be ignored in such case.
                if self.peers.contains_key(&peer_id) {
                    self.destroy_peer(peer_id)?;
                }

                Ok(())
            }
        }
    }

    fn handle_message(&mut self, peer: PeerId, message: Message) -> crate::Result<()> {
        match message {
            Message::Handshake(_) => {
                log::error!("peer {peer} sent handshaking message");
            }
            Message::HeaderListRequest(r) => self.sync_tx.send(SyncingEvent::Message {
                peer,
                message: SyncMessage::HeaderListRequest(r),
            })?,
            Message::BlockListRequest(r) => self.sync_tx.send(SyncingEvent::Message {
                peer,
                message: SyncMessage::BlockListRequest(r),
            })?,
            Message::AddrListRequest(r) => self.conn_tx.send(ConnectivityEvent::Message {
                peer,
                message: PeerManagerMessage::AddrListRequest(r),
            })?,
            Message::AnnounceAddrRequest(r) => self.conn_tx.send(ConnectivityEvent::Message {
                peer,
                message: PeerManagerMessage::AnnounceAddrRequest(r),
            })?,
            Message::PingRequest(r) => self.conn_tx.send(ConnectivityEvent::Message {
                peer,
                message: PeerManagerMessage::PingRequest(r),
            })?,
            Message::HeaderListResponse(r) => self.sync_tx.send(SyncingEvent::Message {
                peer,
                message: SyncMessage::HeaderListResponse(r),
            })?,
            Message::BlockResponse(r) => self.sync_tx.send(SyncingEvent::Message {
                peer,
                message: SyncMessage::BlockResponse(r),
            })?,
            Message::AddrListResponse(r) => self.conn_tx.send(ConnectivityEvent::Message {
                peer,
                message: PeerManagerMessage::AddrListResponse(r),
            })?,
            Message::PingResponse(r) => self.conn_tx.send(ConnectivityEvent::Message {
                peer,
                message: PeerManagerMessage::PingResponse(r),
            })?,
            Message::Announcement(announcement) => self.handle_announcement(peer, *announcement)?,
        }
        Ok(())
    }

    async fn handle_command(&mut self, command: Command<T::Address>) -> crate::Result<()> {
        // All handlings are separated to two parts:
        // - Async (can't take mutable reference to self because they are run concurrently).
        // - Sync (take mutable reference to self because they are run sequentially).
        // Because the second part depends on result of the first part boxed closures are used.

        let backend_task: BackendTask<T> = match command {
            Command::Connect { address } => {
                let connection_fut = timeout(
                    *self.p2p_config.outbound_connection_timeout,
                    self.transport.connect(address.clone()),
                );

                async move {
                    let connection_res = connection_fut.await.unwrap_or(Err(P2pError::DialError(
                        DialError::ConnectionRefusedOrTimedOut,
                    )));

                    boxed_cb(move |this| this.handle_connect_res(address, connection_res))
                }
                .boxed()
            }
            Command::Disconnect { peer_id } => async move {
                boxed_cb(move |this: &mut Self| {
                    let res = this.disconnect_peer(peer_id);
                    if let Err(e) = res {
                        log::debug!("Failed to disconnect peer {peer_id}: {e}")
                    }
                    Ok(())
                })
            }
            .boxed(),
            Command::SendMessage { peer, message } => async move {
                boxed_cb(move |this| {
                    let res = this.send_message(peer, message);
                    if let Err(e) = res {
                        log::debug!("Failed to send request to peer {peer}: {e}")
                    }
                    Ok(())
                })
            }
            .boxed(),
            Command::AnnounceData { topic, message } => async move {
                boxed_cb(move |this| {
                    let res = this.announce_data(topic, message);
                    if let Err(e) = res {
                        log::error!("Failed to send announce data: {e}")
                    }
                    Ok(())
                })
            }
            .boxed(),
        };

        self.command_queue.push(backend_task);

        Ok(())
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

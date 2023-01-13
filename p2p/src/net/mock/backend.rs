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

//! Mock networking backend
//!
//! The backend is modeled after libp2p.
//!
//! The peers are required to have unique IDs which they self-assign to themselves
//! and advertise via the `Hello` message. Until the peer ID has been received, the
//! peers are distinguished by their socket addresses.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use futures::{future::join_all, TryFutureExt};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use common::chain::ChainConfig;
use crypto::random::{make_pseudo_rng, Rng, SliceRandom};
use logging::log;
use serialization::{Decode, Encode};

use crate::{
    config::P2pConfig,
    error::{DialError, P2pError, PeerError, PublishError},
    message,
    net::{
        mock::{
            constants::ANNOUNCEMENT_MAX_SIZE,
            peer, request_manager,
            transport::{TransportListener, TransportSocket},
            types::{
                Command, ConnectivityEvent, Message, MockEvent, MockPeerId, MockPeerInfo,
                MockRequestId, PeerEvent, SyncingEvent,
            },
        },
        types::{PubSubTopic, Role},
        Announcement,
    },
    types::peer_address::PeerAddress,
};

use super::{peer::PeerRole, transport::TransportAddress, types::HandshakeNonce};

/// Active peer data
struct PeerContext {
    subscriptions: BTreeSet<PubSubTopic>,
    tx: mpsc::Sender<MockEvent>,
}

/// Pending peer data (until handshake message is received)
struct PendingPeerContext<A> {
    address: A,
    peer_role: PeerRole,
    tx: mpsc::Sender<MockEvent>,
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
    cmd_rx: mpsc::Receiver<Command<T>>,

    /// Active peers
    peers: HashMap<MockPeerId, PeerContext>,

    /// Pending connections
    pending: HashMap<MockPeerId, PendingPeerContext<T::Address>>,

    /// RX channel for receiving events from peers
    #[allow(clippy::type_complexity)]
    peer_chan: (
        mpsc::Sender<(MockPeerId, PeerEvent)>,
        mpsc::Receiver<(MockPeerId, PeerEvent)>,
    ),

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::Sender<ConnectivityEvent<T>>,

    /// TX channel for sending syncing events
    sync_tx: mpsc::Sender<SyncingEvent>,

    /// Timeout for outbound operations
    timeout: Duration,

    /// Request manager for managing inbound/outbound requests and responses
    request_mgr: request_manager::RequestManager,
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
        cmd_rx: mpsc::Receiver<Command<T>>,
        conn_tx: mpsc::Sender<ConnectivityEvent<T>>,
        sync_tx: mpsc::Sender<SyncingEvent>,
        timeout: Duration,
    ) -> Self {
        Self {
            transport,
            socket,
            cmd_rx,
            conn_tx,
            chain_config,
            p2p_config,
            sync_tx,
            timeout,
            peers: HashMap::new(),
            pending: HashMap::new(),
            peer_chan: mpsc::channel(64),
            request_mgr: request_manager::RequestManager::new(),
        }
    }

    /// Try to establish connection with a remote peer
    async fn connect(
        &mut self,
        address: T::Address,
        response: oneshot::Sender<crate::Result<()>>,
    ) -> crate::Result<()> {
        // For now we always respond with success
        response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)?;

        match timeout(self.timeout, self.transport.connect(address.clone())).await {
            Ok(event) => match event {
                Ok(socket) => {
                    let handshake_nonce = make_pseudo_rng().gen();

                    self.create_peer(
                        socket,
                        MockPeerId::new(),
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
                        .await
                        .map_err(P2pError::from)
                }
            },
            Err(_err) => self
                .conn_tx
                .send(ConnectivityEvent::ConnectionError {
                    address,
                    error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                })
                .await
                .map_err(P2pError::from),
        }
    }

    /// Disconnect remote peer by id
    async fn disconnect_peer(&mut self, peer_id: &MockPeerId) -> crate::Result<()> {
        self.request_mgr.unregister_peer(peer_id);
        if let Some(context) = self.peers.remove(peer_id) {
            context.tx.send(MockEvent::Disconnect).await.map_err(P2pError::from)
        } else {
            // TODO: Think about error handling. Currently we simply follow the libp2p behaviour.
            log::error!("{peer_id} peer doesn't exist");
            Ok(())
        }
    }

    /// Sends a request to the remote peer.
    async fn send_request(
        &mut self,
        peer_id: MockPeerId,
        request: message::Request,
    ) -> crate::Result<MockRequestId> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let (request_id, request) = self.request_mgr.make_request(request)?;
        peer.tx.send(MockEvent::SendMessage(request)).await.map_err(P2pError::from)?;

        Ok(request_id)
    }

    /// Send response to a request
    async fn send_response(
        &mut self,
        request_id: MockRequestId,
        response: message::Response,
    ) -> crate::Result<()> {
        log::trace!("try to send response to request, request id {request_id}");

        if let Some((peer_id, response)) = self.request_mgr.make_response(&request_id, response) {
            return self
                .peers
                .get_mut(&peer_id)
                .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
                .tx
                .send(MockEvent::SendMessage(response))
                .await
                .map_err(P2pError::from);
        }

        log::error!("no request for request id {request_id} exist");
        Ok(())
    }

    /// Sends the announcement to all peers.
    ///
    /// Returns the `InsufficientPeers` error if there are no peers that subscribed to the related
    /// topic.
    async fn announce_data(&mut self, topic: PubSubTopic, message: Vec<u8>) -> crate::Result<()> {
        let announcement = message::Announcement::decode(&mut &message[..])?;

        // Send the message to peers in pseudorandom order.
        let mut futures: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.subscriptions.contains(&topic))
            .map(|(id, peer)| {
                peer.tx
                    .send(MockEvent::SendMessage(Box::new(Message::Announcement {
                        announcement: announcement.clone(),
                    })))
                    .inspect_err(move |e| {
                        log::error!("Failed to send announcement to peer {id}: {e:?}")
                    })
            })
            .collect();
        futures.shuffle(&mut make_pseudo_rng());

        // TODO: We don't really need to return an error here. It is only needed temporarily in
        // order to mimic the libp2p behavior.
        if futures.is_empty() {
            Err(P2pError::PublishError(PublishError::InsufficientPeers))
        } else {
            join_all(futures).await;
            Ok(())
        }
    }

    /// Handle incoming request
    async fn handle_incoming_request(
        &mut self,
        peer_id: MockPeerId,
        request_id: MockRequestId,
        request: message::Request,
    ) -> crate::Result<()> {
        log::trace!("request received from peer {peer_id}, request id {request_id}");

        let request_id = self.request_mgr.register_request(&peer_id, &request_id, &request)?;

        self.sync_tx
            .send(SyncingEvent::Request {
                peer_id,
                request_id,
                request,
            })
            .await
            .map_err(P2pError::from)
    }

    /// Handle incoming response
    async fn handle_incoming_response(
        &mut self,
        peer_id: MockPeerId,
        request_id: MockRequestId,
        response: message::Response,
    ) -> crate::Result<()> {
        log::trace!("response received from peer {peer_id}, request id {request_id}");
        self.sync_tx
            .send(SyncingEvent::Response {
                peer_id,
                request_id,
                response,
            })
            .await
            .map_err(P2pError::from)
    }

    async fn handle_announcement(
        &mut self,
        peer_id: MockPeerId,
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
                .await
                .map_err(P2pError::from)?;
        }

        self.sync_tx
            .send(SyncingEvent::Announcement {
                peer_id,
                announcement: Box::new(announcement),
            })
            .await
            .map_err(P2pError::from)
    }

    /// Runs the backend events loop.
    pub async fn run(&mut self) -> crate::Result<()> {
        loop {
            tokio::select! {
                // Accept a new peer connection.
                res = self.socket.accept() => {
                    let (stream, address) = res.map_err(|_| P2pError::Other("accept() failed"))?;

                    self.create_peer(
                        stream,
                        MockPeerId::new(),
                        PeerRole::Inbound,
                        address,
                    )?;
                }
                // Handle peer events.
                event = self.peer_chan.1.recv() => {
                    let (peer, event) = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_peer_event(peer, event).await?;
                },
                // Handle commands.
                command = self.cmd_rx.recv() => {
                    // TODO: commands running here will block, which means (maybe) these commands in the
                    //       below function should be short-lived. The issue is that connect/disconnect
                    //       functions are part of the handling and they could take a relatively long time
                    //       we should try to figure out how to handle this problem. Maybe we need a separate
                    //       pipeline for commands that are slow, or maybe everything here should go into a new
                    //       task (which sounds excessive).
                    //       Once fixed enable self_connect_channels and self_connect_noise tests.
                    self.handle_command(command.ok_or(P2pError::ChannelClosed)?).await?;
                }
            }
        }
    }

    /// Handle received listening port from inbound remote peer
    fn handle_own_receiver_address(
        &mut self,
        receiver_address: PeerAddress,
        role: Role,
    ) -> crate::Result<()> {
        log::debug!("new own receiver address {receiver_address} found from {role:?} connection");

        // TODO: Handle receiver address

        Ok(())
    }

    /// Create new peer
    ///
    /// Move the connection to `pending` where it stays until either the connection is closed
    /// or the handshake message is received at which point the peer information is moved from
    /// `pending` to `peers` and the front-end is notified about the peer.
    fn create_peer(
        &mut self,
        socket: T::Stream,
        remote_peer_id: MockPeerId,
        peer_role: PeerRole,
        address: T::Address,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel(16);

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
            peer.destroy().await;
        });

        Ok(())
    }

    async fn is_connection_from_self(
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
                    self.pending.remove(&outbound_peer_id).expect("peer must exists");

                log::info!(
                    "self-connection detect on address {:?}",
                    outbound_pending.address
                );

                // Report outbound connection failure
                self.conn_tx
                    .send(ConnectivityEvent::ConnectionError {
                        address: outbound_pending.address,
                        error: P2pError::DialError(DialError::AttemptToDialSelf),
                    })
                    .await
                    .map_err(P2pError::from)?;

                // Nothing else to do, just drop inbound connection
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn handle_peer_event(
        &mut self,
        peer_id: MockPeerId,
        event: PeerEvent,
    ) -> crate::Result<()> {
        match event {
            PeerEvent::PeerInfoReceived {
                network,
                version,
                subscriptions,
                receiver_address,
                handshake_nonce,
            } => {
                let PendingPeerContext {
                    address,
                    peer_role,
                    tx,
                } = match self.pending.remove(&peer_id) {
                    Some(pending) => pending,
                    // Might be removed if self-connection detected
                    None => return Ok(()),
                };

                if self.is_connection_from_self(peer_role, handshake_nonce).await? {
                    return Ok(());
                }

                match peer_role {
                    PeerRole::Outbound { handshake_nonce: _ } => {
                        self.conn_tx
                            .send(ConnectivityEvent::OutboundAccepted {
                                address,
                                peer_info: MockPeerInfo {
                                    peer_id,
                                    network,
                                    version,
                                    agent: None,
                                    subscriptions: subscriptions.clone(),
                                },
                            })
                            .await
                            .map_err(P2pError::from)?;
                    }
                    PeerRole::Inbound => {
                        self.conn_tx
                            .send(ConnectivityEvent::InboundAccepted {
                                address: address.clone(),
                                peer_info: MockPeerInfo {
                                    peer_id,
                                    network,
                                    version,
                                    agent: None,
                                    subscriptions: subscriptions.clone(),
                                },
                            })
                            .await
                            .map_err(P2pError::from)?;
                    }
                }

                if let Some(receiver_address) = receiver_address {
                    self.handle_own_receiver_address(receiver_address, peer_role.into())?;
                }

                self.peers.insert(peer_id, PeerContext { subscriptions, tx });
                let _ = self.request_mgr.register_peer(peer_id);
            }
            PeerEvent::MessageReceived { message } => {
                self.handle_message(peer_id, message).await?;
            }
            PeerEvent::ConnectionClosed => {
                self.pending.remove(&peer_id);
                self.peers.remove(&peer_id);
                self.request_mgr.unregister_peer(&peer_id);

                // Probably ConnectionClosed should be only sent if InboundAccepted or OutboundAccepted was sent before.
                // This can be done by checking self.peers first.
                // But doing so will break some unit tests.
                self.conn_tx
                    .send(ConnectivityEvent::ConnectionClosed { peer_id })
                    .await
                    .map_err(P2pError::from)?;
            }
        }
        Ok(())
    }

    async fn handle_message(&mut self, peer_id: MockPeerId, message: Message) -> crate::Result<()> {
        match message {
            Message::Handshake(_) => {
                log::error!("peer {peer_id} sent handshaking message");
            }
            Message::Request {
                request_id,
                request,
            } => {
                self.handle_incoming_request(peer_id, request_id, request).await?;
            }
            Message::Response {
                request_id,
                response,
            } => {
                self.handle_incoming_response(peer_id, request_id, response).await?;
            }
            Message::Announcement { announcement } => {
                self.handle_announcement(peer_id, announcement).await?;
            }
        }
        Ok(())
    }

    async fn handle_command(&mut self, command: Command<T>) -> crate::Result<()> {
        match command {
            Command::Connect { address, response } => {
                self.connect(address, response).await?;
            }
            Command::Disconnect { peer_id, response } => {
                let res = self.disconnect_peer(&peer_id).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?
            }
            Command::SendRequest {
                peer_id,
                message,
                response,
            } => {
                let res = self.send_request(peer_id, message).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?;
            }
            Command::SendResponse {
                request_id,
                message,
                response,
            } => {
                let res = self.send_response(request_id, message).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?;
            }
            Command::AnnounceData {
                topic,
                message,
                response,
            } => {
                let res = self.announce_data(topic, message).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?;
            }
        }
        Ok(())
    }
}

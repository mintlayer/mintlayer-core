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
    collections::{BTreeMap, BTreeSet, HashMap},
    io::ErrorKind,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::{future::join_all, FutureExt, TryFutureExt};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use common::chain::ChainConfig;
use crypto::random::{make_pseudo_rng, SliceRandom};
use logging::log;
use serialization::{Decode, Encode};

use crate::{
    error::{DialError, P2pError, PeerError, PublishError},
    message,
    net::{
        mock::{
            constants::ANNOUNCEMENT_MAX_SIZE,
            peer, request_manager,
            transport::{GetIp, MockListener, MockTransport},
            types::{
                Command, ConnectivityEvent, Message, MockEvent, MockPeerId, MockPeerInfo,
                MockRequestId, PeerEvent, SyncingEvent,
            },
        },
        types::PubSubTopic,
        Announcement,
    },
};

const BAN_DURATION: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Debug)]
struct PeerContext<T: MockTransport> {
    _peer_id: MockPeerId,
    address: T::Address,
    subscriptions: BTreeSet<PubSubTopic>,
    tx: mpsc::Sender<MockEvent>,
}

#[derive(Debug)]
enum ConnectionState<T: MockTransport> {
    /// Connection established for outbound connection
    OutboundAccepted { address: T::Address },

    /// Connection established for inbound connection
    InboundAccepted { address: T::Address },
}

pub struct Backend<T: MockTransport> {
    /// Socket address of the backend
    address: T::Address,

    /// Socket for listening to incoming connections
    socket: T::Listener,

    /// Chain config
    config: Arc<ChainConfig>,

    /// RX channel for receiving commands from the frontend
    cmd_rx: mpsc::Receiver<Command<T>>,

    /// Active peers
    peers: HashMap<MockPeerId, PeerContext<T>>,

    // TODO: Store banned peers persistently.
    banned_peers: BTreeMap<IpAddr, Duration>,

    /// Pending connections
    pending: HashMap<MockPeerId, (mpsc::Sender<MockEvent>, ConnectionState<T>, T::Address)>,

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
    timeout: std::time::Duration,

    /// Local peer ID
    local_peer_id: MockPeerId,

    /// Request manager for managing inbound/outbound requests and responses
    request_mgr: request_manager::RequestManager,
}

impl<T> Backend<T>
where
    T: MockTransport + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: T::Address,
        socket: T::Listener,
        config: Arc<ChainConfig>,
        cmd_rx: mpsc::Receiver<Command<T>>,
        conn_tx: mpsc::Sender<ConnectivityEvent<T>>,
        sync_tx: mpsc::Sender<SyncingEvent>,
        timeout: std::time::Duration,
    ) -> Self {
        let local_peer_id = MockPeerId::from_socket_address::<T>(&address);
        Self {
            address,
            socket,
            cmd_rx,
            conn_tx,
            config,
            sync_tx,
            timeout,
            peers: HashMap::new(),
            banned_peers: BTreeMap::new(),
            pending: HashMap::new(),
            peer_chan: mpsc::channel(64),
            local_peer_id,
            request_mgr: request_manager::RequestManager::new(),
        }
    }

    /// Try to establish connection with a remote peer
    async fn connect(
        &mut self,
        address: T::Address,
        response: oneshot::Sender<crate::Result<()>>,
    ) -> crate::Result<()> {
        if self.address == address {
            response
                .send(Err(P2pError::DialError(DialError::IoError(
                    ErrorKind::AddrNotAvailable,
                ))))
                .map_err(|_| P2pError::ChannelClosed)?;
        } else {
            response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)?;
        }

        match timeout(self.timeout, T::connect(address.clone())).await {
            Ok(event) => match event {
                Ok(socket) => {
                    self.create_peer(
                        socket,
                        self.local_peer_id,
                        address.clone(),
                        peer::Role::Outbound,
                        ConnectionState::OutboundAccepted { address },
                    )
                    .await
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

    /// Disconnect remote peer
    async fn disconnect_peer(&mut self, peer_id: &MockPeerId) -> crate::Result<()> {
        self.request_mgr.unregister_peer(peer_id);
        self.peers
            .remove(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
            .tx
            .send(MockEvent::Disconnect)
            .await
            .map_err(P2pError::from)
    }

    /// Send request to remote peer
    async fn send_request(
        &mut self,
        peer_id: &MockPeerId,
        request: message::Request,
    ) -> crate::Result<MockRequestId> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let (request_id, request) = self.request_mgr.make_request(peer_id, request)?;

        peer.tx.send(MockEvent::SendMessage(request)).await.map_err(P2pError::from)?;

        Ok(request_id)
    }

    /// Send response to a request
    async fn send_response(
        &mut self,
        request_id: MockRequestId,
        response: message::Response,
    ) -> crate::Result<()> {
        log::trace!(
            "{}: try to send response to request, request id {request_id}",
            self.local_peer_id
        );

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

    async fn subscribe(&mut self, topics: BTreeSet<PubSubTopic>) {
        // Send the message to all peers in pseudorandom order.
        // TODO: This can be moved to a separate function and reused in the `announce_data`
        // function, when we no longer need the special logic for the `InsufficientPeers` error.
        let mut futures: Vec<_> = self
            .peers
            .iter()
            .map(|(id, p)| {
                p.tx.send(MockEvent::SendMessage(Box::new(Message::Subscribe {
                    topics: topics.clone(),
                })))
                .inspect_err(move |e| {
                    log::error!("Failed to send subscription to {id:?} peer: {e:?}")
                })
            })
            .collect();
        futures.shuffle(&mut make_pseudo_rng());

        join_all(futures).await;
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

        self.request_mgr.register_response(&peer_id, &request_id, &response)?;
        self.sync_tx
            .send(SyncingEvent::Response {
                peer_id,
                request_id,
                response,
            })
            .await
            .map_err(P2pError::from)
    }

    fn subscribe_peer(&mut self, peer_id: MockPeerId, topics: BTreeSet<PubSubTopic>) {
        match self.peers.get_mut(&peer_id) {
            Some(peer) => peer.subscriptions = topics.into_iter().collect(),
            None => log::warn!("Unable to subscribe non-existent peer: {peer_id:?}"),
        }
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
                        Some(size),
                        Some(ANNOUNCEMENT_MAX_SIZE),
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
                    self.handle_accept(stream, address).await?;
                }
                // Handle peer events.
                event = self.peer_chan.1.recv().fuse() => {
                    let (peer, event) = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_peer_event(peer, event).await?;
                },
                // Handle commands.
                command = self.cmd_rx.recv().fuse() => {
                    self.handle_command(command.ok_or(P2pError::ChannelClosed)?).await?;
                }
            }
        }
    }

    async fn handle_accept(&mut self, stream: T::Stream, address: T::Address) -> crate::Result<()> {
        // Check if the peer is banned.
        let ip = address.ip();
        if let Some(banned_till) = self.banned_peers.get(&ip) {
            // Check if the ban has expired.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| P2pError::Other("Invalid system time"))?;
            if now > *banned_till {
                self.banned_peers.remove(&ip);
            } else {
                return Err(P2pError::PeerError(PeerError::BannedPeer(format!(
                    "{ip:?}"
                ))));
            }
        }

        self.create_peer(
            stream,
            self.local_peer_id,
            address.clone(),
            peer::Role::Inbound,
            ConnectionState::InboundAccepted { address },
        )
        .await
    }

    /// Create new peer
    ///
    /// Move the connection to `pending` where it stays until either the connection is closed
    /// or the handshake message is received at which point the peer information is moved from
    /// `pending` to `peers` and the front-end is notified about the peer.
    async fn create_peer(
        &mut self,
        socket: T::Stream,
        local_peer_id: MockPeerId,
        peer_address: T::Address,
        role: peer::Role,
        state: ConnectionState<T>,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel(16);

        let remote_peer_id = MockPeerId::from_socket_address::<T>(&peer_address);
        self.pending.insert(remote_peer_id, (tx, state, peer_address));

        let tx = self.peer_chan.0.clone();
        let config = Arc::clone(&self.config);

        tokio::spawn(async move {
            if let Err(err) =
                peer::Peer::<T>::new(local_peer_id, remote_peer_id, role, config, socket, tx, rx)
                    .start()
                    .await
            {
                log::error!("peer {remote_peer_id} failed: {err}");
            }
        });

        Ok(())
    }

    async fn handle_peer_event(
        &mut self,
        peer_id: MockPeerId,
        event: PeerEvent,
    ) -> crate::Result<()> {
        match event {
            PeerEvent::PeerInfoReceived {
                peer_id: received_id,
                network,
                version,
                protocols,
            } => {
                let (tx, state, address) = self.pending.remove(&peer_id).expect("peer to exist");

                match state {
                    ConnectionState::OutboundAccepted { address } => {
                        self.conn_tx
                            .send(ConnectivityEvent::OutboundAccepted {
                                address,
                                peer_info: MockPeerInfo {
                                    peer_id: received_id,
                                    network,
                                    version,
                                    agent: None,
                                    protocols,
                                },
                            })
                            .await
                            .map_err(P2pError::from)?;
                    }
                    ConnectionState::InboundAccepted { address } => {
                        self.conn_tx
                            .send(ConnectivityEvent::InboundAccepted {
                                address,
                                peer_info: MockPeerInfo {
                                    peer_id: received_id,
                                    network,
                                    version,
                                    agent: None,
                                    protocols,
                                },
                            })
                            .await
                            .map_err(P2pError::from)?;
                    }
                }

                self.peers.insert(
                    received_id,
                    PeerContext {
                        _peer_id: received_id,
                        address,
                        subscriptions: BTreeSet::new(),
                        tx,
                    },
                );
                let _ = self.request_mgr.register_peer(received_id);
            }
            PeerEvent::MessageReceived { message } => {
                self.handle_message(peer_id, message).await?;
            }
            PeerEvent::ConnectionClosed => {
                self.peers.remove(&peer_id);
                self.request_mgr.unregister_peer(&peer_id);
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
            Message::Subscribe { topics } => {
                self.subscribe_peer(peer_id, topics);
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
            Command::Disconnect { peer_id, response } |
            // TODO: implement proper banning mechanism
            Command::BanPeer { peer_id, response } => {
                let res = self.ban_peer(&peer_id).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?;
            }
            Command::SendRequest { peer_id, message, response } => {
                let res = self.send_request(&peer_id, message).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?;
            }
            Command::SendResponse { request_id, message, response } => {
                let res = self.send_response(request_id, message).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?;
            }
            Command::Subscribe { topics } => {
                self.subscribe(topics).await;
            }
            Command::AnnounceData { topic, message, response } => {
                let res = self.announce_data(topic, message).await;
                response.send(res).map_err(|_| P2pError::ChannelClosed)?;
            }
        }
        Ok(())
    }

    async fn ban_peer(&mut self, peer: &MockPeerId) -> crate::Result<()> {
        let ip = self
            .peers
            .get(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
            .address
            .ip();
        let ban_till = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| P2pError::Other("Invalid system time"))?
            + BAN_DURATION;
        self.banned_peers.insert(ip, ban_till);
        self.disconnect_peer(peer).await?;
        Ok(())
    }
}

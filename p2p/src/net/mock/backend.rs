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

use std::{collections::HashMap, io::ErrorKind, sync::Arc};

use futures::FutureExt;
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use common::chain::ChainConfig;
use logging::log;

use crate::{
    error::{DialError, P2pError, PeerError},
    message,
    net::mock::{
        peer, request_manager,
        transport::{MockListener, MockTransport},
        types,
    },
};

#[derive(Debug)]
struct PeerContext {
    _peer_id: types::MockPeerId,
    tx: mpsc::Sender<types::MockEvent>,
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
    cmd_rx: mpsc::Receiver<types::Command<T>>,

    /// Active peers
    peers: HashMap<types::MockPeerId, PeerContext>,

    /// Pending connections
    pending: HashMap<types::MockPeerId, (mpsc::Sender<types::MockEvent>, ConnectionState<T>)>,

    /// RX channel for receiving events from peers
    #[allow(clippy::type_complexity)]
    peer_chan: (
        mpsc::Sender<(types::MockPeerId, types::PeerEvent)>,
        mpsc::Receiver<(types::MockPeerId, types::PeerEvent)>,
    ),

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::Sender<types::ConnectivityEvent<T>>,

    /// TX channel for sending syncing events
    sync_tx: mpsc::Sender<types::SyncingEvent>,

    /// TX channel for sending events to the frontend
    _pubsub_tx: mpsc::Sender<types::PubSubEvent<T>>,

    /// Timeout for outbound operations
    timeout: std::time::Duration,

    /// Local peer ID
    local_peer_id: types::MockPeerId,

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
        cmd_rx: mpsc::Receiver<types::Command<T>>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent<T>>,
        _pubsub_tx: mpsc::Sender<types::PubSubEvent<T>>,
        sync_tx: mpsc::Sender<types::SyncingEvent>,
        timeout: std::time::Duration,
    ) -> Self {
        let local_peer_id = types::MockPeerId::from_socket_address::<T>(&address);
        Self {
            address,
            socket,
            cmd_rx,
            conn_tx,
            config,
            _pubsub_tx,
            sync_tx,
            timeout,
            peers: HashMap::new(),
            pending: HashMap::new(),
            peer_chan: mpsc::channel(64),
            local_peer_id,
            request_mgr: request_manager::RequestManager::new(),
        }
    }

    /// Create new peer
    ///
    /// Move the connection to `pending` where it stays until either the connection is closed
    /// or the handshake message is received at which point the peer information is moved from
    /// `pending` to `peers` and the front-end is notified about the peer.
    async fn create_peer(
        &mut self,
        socket: T::Stream,
        local_peer_id: types::MockPeerId,
        remote_peer_id: types::MockPeerId,
        role: peer::Role,
        state: ConnectionState<T>,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel(16);

        self.pending.insert(remote_peer_id, (tx, state));

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
                        types::MockPeerId::from_socket_address::<T>(&address),
                        peer::Role::Outbound,
                        ConnectionState::OutboundAccepted { address },
                    )
                    .await
                }
                Err(err) => {
                    log::error!("Failed to establish connection: {err}");

                    self.conn_tx
                        .send(types::ConnectivityEvent::ConnectionError {
                            address,
                            error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                        })
                        .await
                        .map_err(P2pError::from)
                }
            },
            Err(_err) => self
                .conn_tx
                .send(types::ConnectivityEvent::ConnectionError {
                    address,
                    error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                })
                .await
                .map_err(P2pError::from),
        }
    }

    /// Disconnect remote peer
    async fn disconnect_peer(&mut self, peer_id: &types::MockPeerId) -> crate::Result<()> {
        self.request_mgr.unregister_peer(peer_id);
        self.peers
            .remove(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
            .tx
            .send(types::MockEvent::Disconnect)
            .await
            .map_err(P2pError::from)
    }

    /// Send request to remote peer
    async fn send_request(
        &mut self,
        peer_id: &types::MockPeerId,
        request: message::Request,
    ) -> crate::Result<types::MockRequestId> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let (request_id, request) = self.request_mgr.make_request(peer_id, request)?;

        peer.tx
            .send(types::MockEvent::SendMessage(request))
            .await
            .map_err(P2pError::from)?;

        Ok(request_id)
    }

    /// Send response to a request
    async fn send_response(
        &mut self,
        request_id: types::MockRequestId,
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
                .send(types::MockEvent::SendMessage(response))
                .await
                .map_err(P2pError::from);
        }

        log::error!("no request for request id {request_id} exist");
        Ok(())
    }

    /// Handle incoming request
    async fn handle_incoming_request(
        &mut self,
        peer_id: types::MockPeerId,
        request_id: types::MockRequestId,
        request: message::Request,
    ) -> crate::Result<()> {
        log::trace!("request received from peer {peer_id}, request id {request_id}");

        let request_id = self.request_mgr.register_request(&peer_id, &request_id, &request)?;

        self.sync_tx
            .send(types::SyncingEvent::Request {
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
        peer_id: types::MockPeerId,
        request_id: types::MockRequestId,
        response: message::Response,
    ) -> crate::Result<()> {
        log::trace!("response received from peer {peer_id}, request id {request_id}");

        self.request_mgr.register_response(&peer_id, &request_id, &response)?;
        self.sync_tx
            .send(types::SyncingEvent::Response {
                peer_id,
                request_id,
                response,
            })
            .await
            .map_err(P2pError::from)
    }

    pub async fn run(&mut self) -> crate::Result<()> {
        loop {
            tokio::select! {
                event = self.socket.accept() => match event {
                    Ok(info) => {
                        self.create_peer(
                            info.0,
                            self.local_peer_id,
                            types::MockPeerId::from_socket_address::<T>(&info.1),
                            peer::Role::Inbound,
                            ConnectionState::InboundAccepted { address: info.1 }
                        ).await?;
                    }
                    Err(_err) => return Err(P2pError::Other("accept() failed")),
                },
                event = self.peer_chan.1.recv().fuse() => {
                    let (peer_id, event) = event.ok_or(P2pError::ChannelClosed)?;

                    match event {
                        types::PeerEvent::PeerInfoReceived { peer_id: received_id, network, version, protocols } => {
                            let (tx, state) = self.pending.remove(&peer_id).expect("peer to exist");

                            match state {
                                ConnectionState::OutboundAccepted { address } => {
                                    self.conn_tx.send(types::ConnectivityEvent::OutboundAccepted {
                                        address,
                                        peer_info: types::MockPeerInfo {
                                            peer_id: received_id,
                                            network,
                                            version,
                                            agent: None,
                                            protocols,
                                        }
                                    })
                                    .await
                                    .map_err(P2pError::from)?;
                                }
                                ConnectionState::InboundAccepted { address } => {
                                    self.conn_tx.send(types::ConnectivityEvent::InboundAccepted {
                                        address,
                                        peer_info: types::MockPeerInfo {
                                            peer_id: received_id,
                                            network,
                                            version,
                                            agent: None,
                                            protocols,
                                        }
                                    })
                                    .await
                                    .map_err(P2pError::from)?;
                                }
                            }

                            self.peers.insert(received_id, PeerContext {
                                _peer_id: received_id,
                                tx,
                            });
                            let _ = self.request_mgr.register_peer(received_id);
                        }
                        types::PeerEvent::MessageReceived { message } => match message {
                            types::Message::Handshake(_) => {
                                log::error!("peer {peer_id} sent handshaking message");
                            }
                            types::Message::Request { request_id, request } => {
                                self.handle_incoming_request(peer_id, request_id, request).await?;
                            }
                            types::Message::Response { request_id, response} => {
                                self.handle_incoming_response(peer_id, request_id, response).await?;
                            }
                        }
                        types::PeerEvent::ConnectionClosed => {
                            self.peers.remove(&peer_id);
                            self.request_mgr.unregister_peer(&peer_id);
                            self.conn_tx.send(types::ConnectivityEvent::ConnectionClosed {
                                peer_id,
                            })
                            .await
                            .map_err(P2pError::from)?;
                        }
                    }
                },
                event = self.cmd_rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    types::Command::Connect { address, response } => {
                        self.connect(address, response).await?;
                    }
                    types::Command::Disconnect { peer_id, response } |
                    // TODO: implement proper banning mechanism
                    types::Command::BanPeer { peer_id, response } => {
                        let res = self.disconnect_peer(&peer_id).await;
                        response.send(res).map_err(|_| P2pError::ChannelClosed)?;
                    }
                    types::Command::SendRequest { peer_id, message, response } => {
                        let res = self.send_request(&peer_id, message).await;
                        response.send(res).map_err(|_| P2pError::ChannelClosed)?;
                    }
                    types::Command::SendResponse { request_id, message, response } => {
                        let res = self.send_response(request_id, message).await;
                        response.send(res).map_err(|_| P2pError::ChannelClosed)?;
                    }
                }
            }
        }
    }
}

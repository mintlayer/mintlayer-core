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

use crate::{
    error::{DialError, P2pError, PeerError},
    net::mock::{peer, socket, types},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use std::{collections::HashMap, io::ErrorKind, net::SocketAddr};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::timeout,
};

struct PeerContext {
    _peer_id: types::MockPeerId,
    tx: mpsc::Sender<types::MockEvent>,
}

#[derive(Debug)]
enum ConnectionState {
    /// Connection established for outbound connection
    OutboundAccepted { address: SocketAddr },

    /// Connection established for inbound connection
    InboundAccepted { address: SocketAddr },
}

pub struct Backend {
    /// Socket address of the backend
    address: SocketAddr,

    /// Socket for listening to incoming connections
    socket: TcpListener,

    /// Chain config
    config: Arc<ChainConfig>,

    /// RX channel for receiving commands from the frontend
    cmd_rx: mpsc::Receiver<types::Command>,

    /// Active peers
    peers: HashMap<types::MockPeerId, PeerContext>,

    /// Pending connections
    pending: HashMap<types::MockPeerId, (mpsc::Sender<types::MockEvent>, ConnectionState)>,

    /// RX channel for receiving events from peers
    #[allow(clippy::type_complexity)]
    peer_chan: (
        mpsc::Sender<(types::MockPeerId, types::PeerEvent)>,
        mpsc::Receiver<(types::MockPeerId, types::PeerEvent)>,
    ),

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// TX channel for sending events to the frontend
    _pubsub_tx: mpsc::Sender<types::PubSubEvent>,

    /// Timeout for outbound operations
    timeout: std::time::Duration,
}

impl Backend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: SocketAddr,
        socket: TcpListener,
        config: Arc<ChainConfig>,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        _pubsub_tx: mpsc::Sender<types::PubSubEvent>,
        _sync_tx: mpsc::Sender<types::SyncingEvent>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            address,
            socket,
            cmd_rx,
            conn_tx,
            config,
            _pubsub_tx,
            timeout,
            peers: HashMap::new(),
            pending: HashMap::new(),
            peer_chan: mpsc::channel(64),
        }
    }

    /// Create new peer
    ///
    /// Move the connection to `pending` where it stays until either the connection is closed
    /// or the handshake message is received at which point the peer information is moved from
    /// `pending` to `peers` and the front-end is notified about the peer.
    async fn create_peer(
        &mut self,
        socket: TcpStream,
        local_peer_id: types::MockPeerId,
        remote_peer_id: types::MockPeerId,
        role: peer::Role,
        state: ConnectionState,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel(16);
        let socket = socket::MockSocket::new(socket);

        self.pending.insert(remote_peer_id, (tx, state));

        let tx = self.peer_chan.0.clone();
        let config = Arc::clone(&self.config);

        tokio::spawn(async move {
            if let Err(err) =
                peer::Peer::new(local_peer_id, remote_peer_id, role, config, socket, tx, rx)
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
        address: SocketAddr,
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

        match timeout(self.timeout, TcpStream::connect(address)).await {
            Ok(event) => match event {
                Ok(socket) => {
                    self.create_peer(
                        socket,
                        types::MockPeerId::from_socket_address(&self.address),
                        types::MockPeerId::from_socket_address(&address),
                        peer::Role::Outbound,
                        ConnectionState::OutboundAccepted { address },
                    )
                    .await
                }
                Err(err) => self
                    .conn_tx
                    .send(types::ConnectivityEvent::ConnectionError {
                        address,
                        error: err.into(),
                    })
                    .await
                    .map_err(P2pError::from),
            },
            Err(_err) => self
                .conn_tx
                .send(types::ConnectivityEvent::ConnectionError {
                    address,
                    error: P2pError::DialError(DialError::IoError(
                        std::io::ErrorKind::ConnectionRefused,
                    )),
                })
                .await
                .map_err(P2pError::from),
        }
    }

    pub async fn run(&mut self) -> crate::Result<()> {
        loop {
            tokio::select! {
                event = self.socket.accept() => match event {
                    Ok(info) => {
                        self.create_peer(
                            info.0,
                            types::MockPeerId::from_socket_address(&self.address),
                            types::MockPeerId::from_socket_address(&info.1),
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
                        }
                        types::PeerEvent::ConnectionClosed => {
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
                        match self.peers.remove(&peer_id) {
                            Some(peer) => {
                                let res = peer.tx.send(types::MockEvent::Disconnect).await;
                                response.send(res.map_err(P2pError::from)).map_err(|_| P2pError::ChannelClosed)?;
                            }
                            None => response
                                .send(Err(P2pError::PeerError(PeerError::PeerDoesntExist)))
                                .map_err(|_| P2pError::ChannelClosed)?,
                        }
                    }
                }
            }
        }
    }
}

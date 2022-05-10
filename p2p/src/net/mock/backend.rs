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
#![allow(dead_code, unused_variables, unused_imports, clippy::type_complexity)]
use crate::{
    error::{self, P2pError},
    net::mock::{peer, socket, types},
    net::{NetworkService, PubSubTopic},
};
use async_trait::async_trait;
use common::chain::config;
use crypto::random::{make_pseudo_rng, Rng};
use futures::FutureExt;
use logging::log;
use serialization::{Decode, Encode};
use std::{
    collections::{HashMap, HashSet},
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};

struct PeerContext {
    peer_id: types::MockPeerId,
    tx: mpsc::Sender<types::MockEvent>,
}

#[derive(Debug)]
enum ConnectionState {
    /// Connection established for outbound connection
    OutboundAccepted {
        tx: oneshot::Sender<error::Result<types::MockPeerInfo>>,
    },

    /// Connection established for inbound connection
    InboundAccepted { addr: SocketAddr },
}

pub struct Backend {
    /// Socket address of the backend
    addr: SocketAddr,

    /// Socket for listening to incoming connections
    socket: TcpListener,

    /// Chain config
    config: Arc<config::ChainConfig>,

    /// RX channel for receiving commands from the frontend
    cmd_rx: mpsc::Receiver<types::Command>,

    /// Pending connections
    pending: HashMap<types::MockPeerId, (PeerContext, ConnectionState)>,

    /// Active peers
    peers: HashMap<types::MockPeerId, PeerContext>,

    /// Pending outgoing requests
    req_inbound: HashMap<types::MockRequestId, types::MockPeerId>,

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// RX channel for receiving events from peers
    peer_chan: (
        mpsc::Sender<(types::MockPeerId, types::PeerEvent)>,
        mpsc::Receiver<(types::MockPeerId, types::PeerEvent)>,
    ),

    /// TX channel for sending events to the frontend
    _flood_tx: mpsc::Sender<types::FloodsubEvent>,

    /// TX channel for sending syncing events to the frontend
    sync_tx: mpsc::Sender<types::SyncingEvent>,

    /// Timeout for outbound operations
    timeout: std::time::Duration,
}

impl Backend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: SocketAddr,
        socket: TcpListener,
        config: Arc<config::ChainConfig>,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        _flood_tx: mpsc::Sender<types::FloodsubEvent>,
        sync_tx: mpsc::Sender<types::SyncingEvent>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            config,
            addr,
            socket,
            cmd_rx,
            peers: HashMap::new(),
            pending: HashMap::new(),
            req_inbound: HashMap::new(),
            peer_chan: mpsc::channel(64),
            conn_tx,
            _flood_tx,
            sync_tx,
            timeout,
        }
    }

    async fn create_peer(
        &mut self,
        socket: TcpStream,
        peer_id: types::MockPeerId,
        role: peer::Role,
        state: ConnectionState,
    ) -> error::Result<()> {
        let (tx, rx) = mpsc::channel(16);
        let socket = socket::MockSocket::new(socket);

        self.pending.insert(peer_id, (PeerContext { peer_id, tx }, state));

        let tx = self.peer_chan.0.clone();
        let config = Arc::clone(&self.config);

        tokio::spawn(async move {
            if let Err(e) = peer::Peer::new(peer_id, role, config, socket, tx, rx).start().await {
                log::error!("peer failed: {:?}", e);
            }
        });

        Ok(())
    }

    // TODO: separate into command and event handlers
    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                event = self.socket.accept() => match event {
                    Ok(info) => {
                        self.create_peer(
                            info.0,
                            types::MockPeerId::from_socket_address(&info.1),
                            peer::Role::Inbound,
                            ConnectionState::InboundAccepted { addr: info.1 }
                        ).await?;
                    }
                    Err(e) => {
                        log::error!("accept() failed: {:?}", e);
                        return Err(P2pError::SocketError(e.kind()));
                    }
                },
                event = self.peer_chan.1.recv().fuse() => {
                    let (peer_id, event) = event.ok_or(P2pError::ChannelClosed)?;

                    match event {
                        types::PeerEvent::PeerInfoReceived { net, version, protocols } => {
                            let (ctx, state) = self.pending.remove(&peer_id).expect("peer to exist");

                            match state {
                                ConnectionState::OutboundAccepted { tx } => {
                                    tx.send(Ok(types::MockPeerInfo {
                                        peer_id,
                                        net,
                                        version,
                                        agent: None,
                                        protocols,
                                    })).unwrap();
                                }
                                ConnectionState::InboundAccepted { addr } => {
                                    self.conn_tx.send(types::ConnectivityEvent::IncomingConnection {
                                        addr,
                                        peer_info: types::MockPeerInfo {
                                            peer_id,
                                            net,
                                            version,
                                            agent: None,
                                            protocols,
                                        }
                                    }).await?;
                                }
                            }

                            self.peers.insert(peer_id, ctx);
                        }
                        types::PeerEvent::MessageReceived { message } => match message {
                            types::Message::Handshake(_) => {
                                log::error!("peer {:?} sent handshaking message", peer_id);
                                // TODO: report misbehaviour
                            }
                            types::Message::Syncing(types::SyncingMessage::Request {
                                request_id, request
                            }) => {
                                self.req_inbound.insert(request_id, peer_id);
                                self.sync_tx.send(types::SyncingEvent::Request {
                                    peer_id,
                                    request_id,
                                    request,
                                }).await?;
                            }
                            types::Message::Syncing(types::SyncingMessage::Response {
                                request_id, response
                            }) => {
                                self.sync_tx.send(types::SyncingEvent::Response {
                                    peer_id,
                                    request_id,
                                    response,
                                }).await?;
                            }
                        }
                    }
                },
                event = self.cmd_rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    types::Command::Connect { addr, response } => {
                        if self.addr == addr {
                            let _ = response.send(Err(P2pError::SocketError(ErrorKind::AddrNotAvailable)));
                            continue;
                        }

                        tokio::select! {
                            _ = tokio::time::sleep(self.timeout) => {
                                let _ = response.send(Err(
                                    P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
                                );
                            }
                            res = TcpStream::connect(addr) => match res {
                                Ok(socket) => {
                                    self.create_peer(
                                        socket,
                                        types::MockPeerId::from_socket_address(&addr),
                                        peer::Role::Outbound,
                                        ConnectionState::OutboundAccepted { tx: response }
                                    ).await?;
                                },
                                Err(e) => { let _ = response.send(Err(e.into())); },
                            }
                        }
                    }
                    types::Command::Disconnect { peer_id, response } => {
                        match self.peers.remove(&peer_id) {
                            Some(peer) => {
                                let res = peer.tx.send(types::MockEvent::Disconnect).await;
                                let _ = response.send(res.map_err(P2pError::from));
                            }
                            None => { let _ = response.send(Err(P2pError::PeerDoesntExist)); },
                        }
                    }
                    types::Command::SendRequest { peer_id, message, response } => {
                        match self.peers.get_mut(&peer_id) {
                            Some(peer) => {
                                let request_id = make_pseudo_rng().gen::<types::MockRequestId>();

                                peer.tx.send(types::MockEvent::SendMessage(
                                    Box::new(types::Message::Syncing(types::SyncingMessage::Request {
                                        request_id,
                                        request: message,
                                    }))
                                )).await?;

                                // TODO:
                                let _ = response.send(Ok(request_id));
                            }
                            None => log::error!("peer {:?} does not exist", peer_id),
                        }
                    }
                    types::Command::SendResponse { request_id, message, response } => {
                        match self.req_inbound.remove(&request_id) {
                            Some(peer_id) => {
                                let peer = self
                                    .peers
                                    .get_mut(&peer_id)
                                    .expect("peer to exist") // TODO:
                                    .tx
                                    .send(
                                        types::MockEvent::SendMessage(
                                        Box::new(types::Message::Syncing(types::SyncingMessage::Response {
                                            request_id,
                                            response: message,
                                    })))).await?;
                                    let _ = response.send(Ok(())); // TODO:
                            }
                            None => {
                                log::error!("unknown request id {:?}", request_id);
                            }
                        }
                    }
                }
            }
        }
    }
}

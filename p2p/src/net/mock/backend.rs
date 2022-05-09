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
use futures::FutureExt;
use logging::log;
use serialization::{Decode, Encode};
use std::{
    collections::HashMap,
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
    state: ConnectionState,
}

#[derive(Debug)]
enum ConnectionState {
    /// Outbound connection has been dialed, wait for `ConnectionEstablished` event
    Dialed {
        tx: oneshot::Sender<error::Result<types::MockPeerInfo>>,
    },

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

    /// Active peers
    peers: HashMap<types::MockPeerId, PeerContext>,

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// RX channel for receiving events from peers
    peer_chan: (
        mpsc::Sender<(types::MockPeerId, types::PeerEvent)>,
        mpsc::Receiver<(types::MockPeerId, types::PeerEvent)>,
    ),

    /// TX channel for sending events to the frontend
    _flood_tx: mpsc::Sender<types::FloodsubEvent>,

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
        _sync_tx: mpsc::Sender<types::SyncingEvent>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            config,
            addr,
            socket,
            cmd_rx,
            peers: HashMap::new(),
            peer_chan: mpsc::channel(64),
            conn_tx,
            _flood_tx,
            timeout,
        }
    }

    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                event = self.socket.accept() => match event {
                    Ok(info) => {
                        let (tx, rx) = mpsc::channel(16);
                        let peer_id = types::MockPeerId::from_socket_address(&info.1);
                        let socket = socket::MockSocket::new(info.0);

                        self.peers.insert(peer_id, PeerContext {
                            peer_id,
                            tx,
                            state: ConnectionState::InboundAccepted { addr: info.1 },
                        });

                        let tx = self.peer_chan.0.clone();
                        let config = Arc::clone(&self.config);

                        tokio::spawn(async move {
                            if let Err(e) = peer::Peer::new(
                                peer_id,
                                peer::Role::Inbound,
                                config,
                                socket,
                                tx,
                                rx
                            ).start().await {
                                log::error!("peer failed: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("accept() failed: {:?}", e);
                        return Err(P2pError::SocketError(e.kind()));
                    }
                },
                event = self.peer_chan.1.recv().fuse() => {
                    let (peer_id, event) = event.ok_or(P2pError::ChannelClosed)?;

                    match event {
                        types::PeerEvent::PeerInfoReceived { network, version, protocols } => {
                            match self.peers.remove(&peer_id).expect("zzz").state {
                                ConnectionState::Dialed { .. } => panic!("zzz"),
                                ConnectionState::InboundAccepted { addr } => {
                                    todo!();
                                }
                                ConnectionState::OutboundAccepted { tx } => {
                                    todo!();
                                }
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

                        todo!();
                    }
                }
            }
        }
    }
}

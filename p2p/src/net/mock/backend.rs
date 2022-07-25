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
use crate::{
    error::{DialError, P2pError},
    net::mock::{peer, socket, types},
};
use futures::FutureExt;
use logging::log;
use std::{collections::HashMap, io::ErrorKind, net::SocketAddr};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};

struct PeerContext {
    peer_id: types::MockPeerId,
    tx: mpsc::Sender<types::PeerEvent>,
    state: ConnectionState,
}

#[derive(Debug)]
enum ConnectionState {
    /// Outbound connection has been dialed, wait for `ConnectionEstablished` event
    Dialed {
        tx: oneshot::Sender<crate::Result<types::MockPeerInfo>>,
    },

    /// Connection established for outbound connection
    OutboundAccepted {
        tx: oneshot::Sender<crate::Result<types::MockPeerInfo>>,
    },

    /// Connection established for inbound connection
    InboundAccepted { addr: SocketAddr },
}

pub struct Backend {
    /// Socket address of the backend
    addr: SocketAddr,

    /// Socket for listening to incoming connections
    socket: TcpListener,

    /// RX channel for receiving commands from the frontend
    cmd_rx: mpsc::Receiver<types::Command>,

    /// Active peers
    peers: HashMap<types::MockPeerId, PeerContext>,

    /// RX channel for receiving events from peers
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
    pub fn new(
        addr: SocketAddr,
        socket: TcpListener,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        _pubsub_tx: mpsc::Sender<types::PubSubEvent>,
        _sync_tx: mpsc::Sender<types::SyncingEvent>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            addr,
            socket,
            cmd_rx,
            conn_tx,
            _pubsub_tx,
            timeout,
            peers: HashMap::new(),
            peer_chan: mpsc::channel(64),
        }
    }

    pub async fn run(&mut self) -> crate::Result<()> {
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
                        tokio::spawn(async move {
                            if let Err(e) = peer::Peer::new(peer_id, socket, tx, rx).start().await {
                                log::error!("peer failed: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("accept() failed: {:?}", e);
                        return Err(P2pError::Other("accept() failed"));
                    }
                },
                event = self.peer_chan.1.recv().fuse() => {
                    let (_peer_id, event) = event.ok_or(P2pError::ChannelClosed)?;

                    match event {
                        types::PeerEvent::Dummy => {
                            todo!();
                        }
                    }
                },
                event = self.cmd_rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    types::Command::Connect { addr, response } => {
                        if self.addr == addr {
                            let _ = response.send(Err(P2pError::DialError(DialError::IoError(ErrorKind::AddrNotAvailable))));
                            continue;
                        }

                        tokio::select! {
                            _ = tokio::time::sleep(self.timeout) => {
                                let _ = response.send(Err(
                                    P2pError::DialError(DialError::IoError(std::io::ErrorKind::ConnectionRefused))
                                ));
                            }
                            res = TcpStream::connect(addr) => match res {
                                Ok(socket) => { let _ = response.send(Ok(socket)); },
                                Err(e) => { let _ = response.send(Err(e.into())); },
                            }
                        }
                    }
                }
            }
        }
    }
}

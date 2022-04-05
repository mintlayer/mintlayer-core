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
#![allow(dead_code, unused_variables, unused_imports)]
use crate::{
    error::{self, P2pError},
    net::mock::{floodsub, types, MockSocket},
    net::{FloodsubTopic, NetworkService, SocketService},
    peer::Peer,
};
use async_trait::async_trait;
use futures::FutureExt;
use logging::log;
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::{HashMap, HashSet},
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

enum Role {
    Inbound,
    Outbound,
}

pub struct Backend {
    /// Socket address of the backend
    addr: SocketAddr,

    /// Socket for listening to incoming connections
    socket: TcpListener,

    /// RX channel for receiving commands from the frontend
    cmd_rx: mpsc::Receiver<types::Command>,

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// TX channel for sending commands to the floodsub backend
    floodmgr_tx: mpsc::Sender<types::FloodsubCommand>,

    /// Floodsub topics that the local node is subscribed to
    flood_topics: Vec<FloodsubTopic>,

    /// Set of known but unregistered peers
    unregistered: HashMap<SocketAddr, (TcpStream, Vec<FloodsubTopic>)>,
}

impl Backend {
    pub fn new(
        addr: SocketAddr,
        socket: TcpListener,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        flood_tx: mpsc::Sender<types::FloodsubEvent>,
        flood_topics: Vec<FloodsubTopic>,
    ) -> Self {
        let (floodmgr_tx, floodmgr_rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let mut floodmgr = floodsub::Floodsub::new(flood_tx, floodmgr_rx);
            if let Err(e) = floodmgr.run().await {
                log::error!("mock floodsub manager failed: {:?}", e);
            }
        });

        Self {
            addr,
            socket,
            cmd_rx,
            conn_tx,
            floodmgr_tx,
            flood_topics,
            unregistered: HashMap::new(),
        }
    }

    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                event = self.socket.accept() => match event {
                    Ok(mut socket) => {
                        self.exchange_floodsub_info(&mut socket.0, socket.1, Role::Inbound).await?;
                        self.conn_tx.send(types::ConnectivityEvent::IncomingConnection {
                            peer_id: socket.1,
                            socket: socket.0,
                        }).await?;
                    }
                    Err(e) => {
                        log::error!("accept() failed: {:?}", e);
                        return Err(P2pError::SocketError(e.kind()));
                    }
                },
                event = self.cmd_rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    types::Command::Connect { addr, response } => {
                        if self.addr == addr {
                            let _ = response.send(
                                Err(P2pError::SocketError(ErrorKind::AddrNotAvailable))
                            );
                            continue;
                        }

                        let _ = match TcpStream::connect(addr).await {
                            Ok(mut socket) => {
                                self.exchange_floodsub_info(&mut socket, addr, Role::Outbound).await?;
                                response.send(Ok((addr, socket)))
                            },
                            Err(e) => response.send(Err(e.into())),
                        };
                    },
                    types::Command::SendMessage { topic, message, response } => {
                        self.floodmgr_tx.send(types::FloodsubCommand::SendMessage {
                            topic, message, response
                        }).await.map_err(|_| P2pError::ChannelClosed)?;
                    }
                    types::Command::RegisterPeer { peer, response } => {
                        let res = if let Some((socket, topics)) = self.unregistered.remove(&peer) {
                            self.floodmgr_tx.send(types::FloodsubCommand::PeerConnected {
                                peer,
                                socket: MockSocket::new(socket),
                                topics,
                            }).await.map_err(|_| P2pError::ChannelClosed)
                        } else {
                            log::error!("peer {:?} does not exist", peer);
                            Err(P2pError::PeerDoesntExist)
                        };

                        response
                            .send(res)
                            .map_err(|_| P2pError::ChannelClosed)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                    types::Command::UnregisterPeer { peer, response } => {
                        let res = self.floodmgr_tx.send(types::FloodsubCommand::PeerDisconnected {
                            peer,
                        }).await.map_err(|_| P2pError::ChannelClosed);
                        response
                            .send(res)
                            .map_err(|_| P2pError::ChannelClosed)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                }
            }
        }
    }

    /// Exchange floodsub information with the remote node
    async fn exchange_floodsub_info(
        &mut self,
        socket: &mut TcpStream,
        peer_id: SocketAddr,
        role: Role,
    ) -> error::Result<()> {
        let (flood_socket, topics) = match role {
            Role::Inbound => {
                let addr = format!(
                    "[::1]:{}",
                    portpicker::pick_unused_port().expect("port to be available")
                )
                .parse()
                .expect("address to be valid");

                let server = TcpListener::bind(addr).await?;
                self.send_floodsub_info(socket, addr).await?;
                let (mut flood_socket, _) = server.accept().await?;
                let (_, topics) = self.recv_floodsub_info(&mut flood_socket).await?;

                (flood_socket, topics)
            }
            Role::Outbound => {
                let (addr, topics) = self.recv_floodsub_info(socket).await?;
                let mut flood_socket = TcpStream::connect(addr).await?;
                let local_addr = flood_socket.local_addr()?;
                self.send_floodsub_info(&mut flood_socket, local_addr).await?;

                (flood_socket, topics)
            }
        };

        self.unregistered.insert(peer_id, (flood_socket, topics));
        Ok(())
    }

    /// Send local node's floodsub information to remote node
    async fn send_floodsub_info(
        &mut self,
        socket: &mut TcpStream,
        addr: SocketAddr,
    ) -> error::Result<()> {
        log::debug!(
            "send floodsub address ({:?}) and topics ({:?}) to remote",
            addr,
            self.flood_topics
        );

        for data in [addr.to_string().encode(), self.flood_topics.encode()] {
            let data_len = (data.len() as u32).encode();
            let _ = socket.write(&data_len).await?;
            let _ = socket.write(&data).await?;
        }

        Ok(())
    }

    // TODO: use `MockSocket` to read these?

    /// Read size of the incoming message from the socket
    async fn read_size(&mut self, socket: &mut TcpStream) -> error::Result<u32> {
        let size: u32 = 0u32;
        let mut data = vec![0u8; size.encoded_size()];

        match socket.read_exact(&mut data).await {
            Ok(_) => Ok(Decode::decode(&mut &data[..])?),
            Err(_) => Err(P2pError::PeerDisconnected),
        }
    }

    /// Receiver remote node's floodsub information
    async fn recv_floodsub_info(
        &mut self,
        socket: &mut TcpStream,
    ) -> error::Result<(SocketAddr, Vec<FloodsubTopic>)> {
        let mut data = vec![0u8; 1024 * 1024];

        let size = self.read_size(socket).await?;
        data.resize(size as usize, 0);

        let address: SocketAddr = match socket.read_exact(&mut data).await? {
            0 => return Err(P2pError::PeerDisconnected),
            _ => match String::decode(&mut &data[..]) {
                Ok(addr_string) => match addr_string.parse() {
                    Ok(socket_addr) => socket_addr,
                    Err(_) => {
                        return Err(P2pError::DecodeFailure(
                            "Failed to parse socket address string".to_string(),
                        ))
                    }
                },
                Err(_) => {
                    return Err(P2pError::DecodeFailure(
                        "Failed to decode String".to_string(),
                    ))
                }
            },
        };

        let size = self.read_size(socket).await?;
        data.resize(size as usize, 0);

        let topics: Vec<FloodsubTopic> = match socket.read(&mut data).await? {
            0 => return Err(P2pError::PeerDisconnected),
            _ => Decode::decode(&mut &data[..])
                .map_err(|e| P2pError::DecodeFailure(e.to_string()))?,
        };

        log::debug!(
            "received floodsub address ({:?}) and topics ({:?}) from remote",
            address,
            topics
        );

        Ok((address, topics))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_floodsub_exchange() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let addr2: SocketAddr = test_utils::make_address("[::1]:");
        let listener = TcpListener::bind(addr).await.unwrap();
        let listener2 = TcpListener::bind(addr2).await.unwrap();
        let conn = TcpStream::connect(addr);

        let (res1, res2) = tokio::join!(listener.accept(), conn);
        let (mut socket2, _) = res1.unwrap();
        let mut socket1 = res2.unwrap();

        let (_, cmd_rx) = mpsc::channel(1);
        let (_, cmd2_rx) = mpsc::channel(1);
        let (conn_tx, _) = mpsc::channel(1);
        let (flood_tx, _) = mpsc::channel(1);

        let peer1 = test_utils::make_address("[::1]:");
        let mut backend1 = Backend::new(
            peer1,
            listener,
            cmd_rx,
            conn_tx.clone(),
            flood_tx.clone(),
            vec![FloodsubTopic::Blocks],
        );

        let peer2 = test_utils::make_address("[::1]:");
        let mut backend2 = Backend::new(
            peer2,
            listener2,
            cmd2_rx,
            conn_tx,
            flood_tx,
            vec![FloodsubTopic::Blocks, FloodsubTopic::Transactions],
        );

        let (res1, res2) = tokio::join!(
            backend1.exchange_floodsub_info(&mut socket1, peer2, Role::Inbound),
            backend2.exchange_floodsub_info(&mut socket2, peer1, Role::Outbound)
        );

        let unreg_peer1 = backend1.unregistered.iter().next().unwrap();
        let unreg_peer2 = backend2.unregistered.iter().next().unwrap();

        assert_eq!(unreg_peer1.0, &peer2);
        assert_eq!(unreg_peer2.0, &peer1);

        assert_eq!(
            unreg_peer1.1 .1,
            vec![FloodsubTopic::Blocks, FloodsubTopic::Transactions]
        );
        assert_eq!(unreg_peer2.1 .1, vec![FloodsubTopic::Blocks]);
    }
}

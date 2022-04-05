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
#![allow(unused)]
#![allow(clippy::type_complexity)]

use crate::{
    error::{self, P2pError},
    message::Message,
    net::mock::{floodsub, types},
    net::{mock::MockSocket, FloodsubTopic, NetworkService, SocketService},
    peer::Peer,
};
use async_trait::async_trait;
use futures::FutureExt;
use logging::log;
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc},
};

#[derive(Debug, PartialEq, Eq, Encode, Decode, Hash)]
pub struct FloodsubMessage {
    topic: FloodsubTopic,
    message: Vec<u8>,
}

pub struct Floodsub {
    /// TX channel for sending events to the frontend
    event_tx: mpsc::Sender<types::FloodsubEvent>,

    /// RX channel for receiving commands from the backend
    cmd_rx: mpsc::Receiver<types::FloodsubCommand>,

    /// Set of peers
    peers: HashMap<SocketAddr, mpsc::Sender<()>>,

    /// Set of subscriptions
    subscriptions: HashMap<FloodsubTopic, HashSet<SocketAddr>>,

    /// Broadcast channel for sending messages to the sockets
    broadcast: (
        broadcast::Sender<(FloodsubTopic, Vec<u8>)>,
        broadcast::Receiver<(FloodsubTopic, Vec<u8>)>,
    ),

    /// Channels for receiving messages from the sockets
    msg_chan: (
        mpsc::Sender<(SocketAddr, FloodsubMessage)>,
        mpsc::Receiver<(SocketAddr, FloodsubMessage)>,
    ),

    /// All messages that have been received and forwarded to frontend
    seen_messages: HashSet<u64>,
}

fn get_message_hash(msg: &FloodsubMessage) -> u64 {
    let mut hasher = DefaultHasher::new();
    msg.hash(&mut hasher);
    hasher.finish()
}

async fn peer_loop(
    peer: SocketAddr,
    mut socket: MockSocket,
    mut shutdown_rx: mpsc::Receiver<()>,
    mut msg_rx: broadcast::Receiver<(FloodsubTopic, Vec<u8>)>,
    mut msg_tx: mpsc::Sender<(SocketAddr, FloodsubMessage)>,
) -> error::Result<()> {
    let mut seen_messages: HashSet<u64> = HashSet::new();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv().fuse() => {
                return Ok(());
            },
            msg = socket.recv() => {
                let msg: FloodsubMessage = msg?;
                let hash = get_message_hash(&msg);

                if !seen_messages.contains(&hash) {
                    msg_tx.send((peer, msg)).await;
                }
                seen_messages.insert(hash);
            }
            msg = msg_rx.recv() => {
                let (topic, message) = msg.map_err(|_| P2pError::ChannelClosed)?;
                let msg = FloodsubMessage { topic, message };
                let hash = get_message_hash(&msg);

                if !seen_messages.contains(&hash) {
                    socket.send(&msg).await;
                }
                seen_messages.insert(hash);
            }
        }
    }
}

impl Floodsub {
    pub fn new(
        event_tx: mpsc::Sender<types::FloodsubEvent>,
        cmd_rx: mpsc::Receiver<types::FloodsubCommand>,
    ) -> Self {
        Self {
            event_tx,
            cmd_rx,
            peers: HashMap::new(),
            subscriptions: HashMap::new(),
            seen_messages: HashSet::new(),
            broadcast: broadcast::channel(16),
            msg_chan: mpsc::channel(16),
        }
    }

    async fn handle_cmd(&mut self, cmd: types::FloodsubCommand) -> error::Result<()> {
        match cmd {
            types::FloodsubCommand::PeerConnected {
                peer,
                mut socket,
                topics,
            } => {
                let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
                let msg_rx = self.broadcast.0.subscribe();
                let msg_tx = self.msg_chan.0.clone();

                tokio::spawn(async move {
                    if let Err(e) = peer_loop(peer, socket, shutdown_rx, msg_rx, msg_tx).await {
                        log::error!("floodsub loop for peer {:?} failed: {:?}", peer, e);
                    }
                });

                self.peers.insert(peer, shutdown_tx);
                topics.into_iter().for_each(|topic| {
                    self.subscriptions.entry(topic).or_insert_with(HashSet::new).insert(peer);
                })
            }
            types::FloodsubCommand::PeerDisconnected { peer } => {
                if let Some(channel) = self.peers.remove(&peer) {
                    channel.send(()).await;
                    self.subscriptions.iter_mut().for_each(|entry| {
                        entry.1.remove(&peer);
                    });
                }
            }
            types::FloodsubCommand::SendMessage {
                topic,
                message,
                response,
            } => {
                let res = match self.subscriptions.get(&topic) {
                    Some(subscribers) => {
                        if subscribers.is_empty() {
                            return Err(P2pError::NoPeers);
                        }

                        self.broadcast
                            .0
                            .send((topic, message))
                            .map(|_| ())
                            .map_err(|_| P2pError::ChannelClosed)
                    }
                    None => Err(P2pError::NoPeers),
                };

                response
                    .send(res)
                    .map_err(|_| P2pError::ChannelClosed)
                    .map_err(|_| P2pError::ChannelClosed)?;
            }
        }

        Ok(())
    }

    async fn handle_msg(
        &mut self,
        peer: SocketAddr,
        message: FloodsubMessage,
    ) -> error::Result<()> {
        let hash = get_message_hash(&message);

        if !self.seen_messages.contains(&hash) {
            self.event_tx
                .send(types::FloodsubEvent::MessageReceived {
                    peer_id: peer,
                    topic: message.topic,
                    message: message.message.clone(),
                })
                .await
                .map_err(|_| P2pError::ChannelClosed)?;
        }

        self.seen_messages.insert(hash);
        self.broadcast
            .0
            .send((message.topic, message.message))
            .map(|_| ())
            .map_err(|_| P2pError::ChannelClosed);
        Ok(())
    }

    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => {
                    self.handle_cmd(cmd.ok_or(P2pError::ChannelClosed)?).await?;
                },
                msg = self.msg_chan.1.recv().fuse() => {
                    let (peer, message) = msg.ok_or(P2pError::ChannelClosed)?;
                    self.handle_msg(peer, message).await?;

                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    async fn get_connected_socket() -> (TcpStream, TcpStream) {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let listener = TcpListener::bind(addr).await.unwrap();
        let stream = TcpStream::connect(addr);
        let (res1, res2) = tokio::join!(listener.accept(), stream);

        (res1.unwrap().0, res2.unwrap())
    }

    #[tokio::test]
    async fn register_peer() {
        let (tx, _) = mpsc::channel(1);
        let (_, rx) = mpsc::channel(1);
        let mut floodsub = Floodsub::new(tx, rx);

        let peer = test_utils::get_random_mock_id();
        assert_eq!(
            floodsub
                .handle_cmd(types::FloodsubCommand::PeerConnected {
                    peer,
                    socket: MockSocket::new(get_connected_socket().await.0),
                    topics: vec![FloodsubTopic::Blocks],
                })
                .await,
            Ok(())
        );

        assert!(floodsub.peers.contains_key(&peer));
        assert_eq!(
            floodsub.subscriptions,
            HashMap::from([(FloodsubTopic::Blocks, HashSet::from([(peer)]))])
        );
    }

    #[tokio::test]
    async fn unregister_peer_that_doesnt_exist() {
        let (tx, _) = mpsc::channel(1);
        let (_, rx) = mpsc::channel(1);
        let mut floodsub = Floodsub::new(tx, rx);

        assert!(floodsub.peers.is_empty());
        assert!(floodsub.subscriptions.is_empty());

        assert_eq!(
            floodsub
                .handle_cmd(types::FloodsubCommand::PeerDisconnected {
                    peer: test_utils::get_random_mock_id(),
                })
                .await,
            Ok(())
        );

        assert!(floodsub.peers.is_empty());
        assert!(floodsub.subscriptions.is_empty());
    }

    #[tokio::test]
    async fn register_then_unregister_peer() {
        let (tx, _) = mpsc::channel(1);
        let (_, rx) = mpsc::channel(1);
        let mut floodsub = Floodsub::new(tx, rx);

        let peer = test_utils::get_random_mock_id();
        assert_eq!(
            floodsub
                .handle_cmd(types::FloodsubCommand::PeerConnected {
                    peer,
                    socket: MockSocket::new(get_connected_socket().await.0),
                    topics: vec![FloodsubTopic::Blocks],
                })
                .await,
            Ok(())
        );

        assert!(floodsub.peers.contains_key(&peer));
        assert_eq!(
            floodsub.subscriptions,
            HashMap::from([(FloodsubTopic::Blocks, HashSet::from([(peer)]))])
        );

        assert_eq!(
            floodsub.handle_cmd(types::FloodsubCommand::PeerDisconnected { peer }).await,
            Ok(())
        );

        assert!(floodsub.peers.is_empty());
        assert_eq!(
            floodsub.subscriptions,
            HashMap::from([(FloodsubTopic::Blocks, HashSet::from([]))])
        );
    }

    #[tokio::test]
    async fn publish_data_no_peers() {
        let (tx, _) = mpsc::channel(1);
        let (_, rx) = mpsc::channel(1);
        let mut floodsub = Floodsub::new(tx, rx);
        let (response_tx, response_rx) = oneshot::channel();

        assert_eq!(
            floodsub
                .handle_cmd(types::FloodsubCommand::SendMessage {
                    topic: FloodsubTopic::Blocks,
                    message: vec![1, 2, 3, 4, 5],
                    response: response_tx,
                })
                .await,
            Ok(()),
        );
        assert_eq!(response_rx.await.unwrap(), Err(P2pError::NoPeers));
    }

    #[tokio::test]
    async fn register_two_peers_publish_data() {
        let ((peer1_sockets, peer1_id)) = (
            get_connected_socket().await,
            test_utils::get_random_mock_id(),
        );
        let ((peer2_sockets, peer2_id)) = (
            get_connected_socket().await,
            test_utils::get_random_mock_id(),
        );

        let (tx, _) = mpsc::channel(1);
        let (_, rx) = mpsc::channel(1);
        let (response_tx, response_rx) = oneshot::channel();
        let mut floodsub = Floodsub::new(tx, rx);

        floodsub
            .handle_cmd(types::FloodsubCommand::PeerConnected {
                peer: peer1_id,
                socket: MockSocket::new(peer1_sockets.0),
                topics: vec![FloodsubTopic::Blocks],
            })
            .await
            .unwrap();

        floodsub
            .handle_cmd(types::FloodsubCommand::PeerConnected {
                peer: peer2_id,
                socket: MockSocket::new(peer2_sockets.0),
                topics: vec![FloodsubTopic::Blocks],
            })
            .await
            .unwrap();

        floodsub
            .handle_cmd(types::FloodsubCommand::SendMessage {
                topic: FloodsubTopic::Blocks,
                message: vec![1, 2, 3, 4, 5],
                response: response_tx,
            })
            .await
            .unwrap();

        assert_eq!(response_rx.await.unwrap(), Ok(()));

        for mut peer_socket in [MockSocket::new(peer1_sockets.1), MockSocket::new(peer2_sockets.1)]
        {
            assert_eq!(
                peer_socket.recv().await,
                Ok(FloodsubMessage {
                    topic: FloodsubTopic::Blocks,
                    message: vec![1, 2, 3, 4, 5],
                })
            );
        }
    }

    #[tokio::test]
    async fn receive_data() {
        let ((peer_sockets, peer)) = (
            get_connected_socket().await,
            test_utils::get_random_mock_id(),
        );

        let (tx, mut event_rx) = mpsc::channel(1);
        let (_, rx) = mpsc::channel(1);
        let mut floodsub = Floodsub::new(tx, rx);

        floodsub
            .handle_cmd(types::FloodsubCommand::PeerConnected {
                peer,
                socket: MockSocket::new(peer_sockets.0),
                topics: vec![FloodsubTopic::Blocks],
            })
            .await
            .unwrap();

        let mut socket = MockSocket::new(peer_sockets.1);
        socket
            .send(&FloodsubMessage {
                topic: FloodsubTopic::Blocks,
                message: vec![13, 37, 13, 38],
            })
            .await
            .unwrap();

        // receive the message from peer
        let res = floodsub.msg_chan.1.recv().await.unwrap();
        floodsub.handle_msg(res.0, res.1).await.unwrap();

        assert_eq!(
            event_rx.recv().await,
            Some(types::FloodsubEvent::MessageReceived {
                peer_id: res.0,
                topic: FloodsubTopic::Blocks,
                message: vec![13, 37, 13, 38],
            })
        );

        // try to receive the same message again, this time it is not forwarded to the frontend
        socket
            .send(&FloodsubMessage {
                topic: FloodsubTopic::Blocks,
                message: vec![13, 37, 13, 38],
            })
            .await
            .unwrap();
        assert_eq!(
            floodsub.msg_chan.1.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
    }

    #[tokio::test]
    async fn receive_data_verify_forwarding() {
        let ((peer1_sockets, peer1_id)) = (
            get_connected_socket().await,
            test_utils::get_random_mock_id(),
        );
        let ((peer2_sockets, peer2_id)) = (
            get_connected_socket().await,
            test_utils::get_random_mock_id(),
        );

        let (tx, mut event_rx) = mpsc::channel(1);
        let (_, rx) = mpsc::channel(1);
        let mut floodsub = Floodsub::new(tx, rx);

        floodsub
            .handle_cmd(types::FloodsubCommand::PeerConnected {
                peer: peer1_id,
                socket: MockSocket::new(peer1_sockets.0),
                topics: vec![FloodsubTopic::Blocks],
            })
            .await
            .unwrap();

        floodsub
            .handle_cmd(types::FloodsubCommand::PeerConnected {
                peer: peer2_id,
                socket: MockSocket::new(peer2_sockets.0),
                topics: vec![FloodsubTopic::Blocks],
            })
            .await
            .unwrap();

        let mut socket1 = MockSocket::new(peer1_sockets.1);
        let mut socket2 = MockSocket::new(peer2_sockets.1);

        socket1
            .send(&FloodsubMessage {
                topic: FloodsubTopic::Blocks,
                message: vec![13, 37, 13, 38],
            })
            .await
            .unwrap();

        // receive the message from peer
        let res = floodsub.msg_chan.1.recv().await.unwrap();
        floodsub.handle_msg(res.0, res.1).await.unwrap();

        assert_eq!(
            event_rx.recv().await,
            Some(types::FloodsubEvent::MessageReceived {
                peer_id: res.0,
                topic: FloodsubTopic::Blocks,
                message: vec![13, 37, 13, 38],
            })
        );

        // verify that the other connected peer also received the message
        assert_eq!(
            socket2.recv().await,
            Ok(FloodsubMessage {
                topic: FloodsubTopic::Blocks,
                message: vec![13, 37, 13, 38],
            })
        );

        // try to receive the same message again, this time it is not forwarded to the frontend
        socket1
            .send(&FloodsubMessage {
                topic: FloodsubTopic::Blocks,
                message: vec![13, 37, 13, 38],
            })
            .await
            .unwrap();
        assert_eq!(
            floodsub.msg_chan.1.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
    }
}

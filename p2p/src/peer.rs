// Copyright (c) 2021 RBB S.r.l
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
    error::{self, P2pError, ProtocolError},
    event::{Event, PeerEvent},
    message::{HandshakeMessage, Message, MessageType},
    net::{NetworkService, SocketService},
    proto::{connectivity::*, handshake::*},
};
use common::{chain::ChainConfig, primitives::time};
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use futures_timer::Delay;
use std::{sync::Arc, time::Duration};

pub type PeerId = u64;
pub type TaskId = u64;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    pub task: Task,
    pub period: i64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ListeningState {
    /// Listen to and handle all incoming messages
    Any,

    /// Listen to and handle all incoming messages but expect
    /// to receive Pong message from remote
    Connectivity(ConnectivityState),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PeerState {
    /// Peer is handshaking with the remote peer
    Handshaking(HandshakeState),

    /// Listen to incoming messages from remote peer
    Listening(ListeningState),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PeerRole {
    /// Peer accepted a connection from remote
    Inbound,

    /// Peer initiated a connection to remote
    Outbound,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectivityTask {
    Ping {
        /// How often is Ping scheduled to happen (seconds)
        period: i64,
    },
    PingRetry {
        /// How many times the Ping has been resent
        max_retries: isize,
    },
}

/// Task is an abstraction over some piece of code
/// that is scheduled to happen either periodically
/// (such as the ping task once a minute) or in one-shot
/// fashion (such as the ping retry task).
///
/// It's a wrapper for an asynchronous timer which returns
/// the task type when it expires and allows the peer event
/// loop to handle it alongside with any other event received
/// either from the socket or from P2P's RX channel.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Task {
    Connectivity(ConnectivityTask),
}

/// How often (in seconds) is ping/pong scheduled to happen
pub const PING_PERIOD: i64 = 60;

/// How long is the response to ping waited until ping is sent again
pub const PING_REPLY_PERIOD: i64 = 10;

/// How many times is ping resent until the remote is considered unresponsive
pub const PING_MAX_RETRIES: isize = 3;

pub async fn schedule_event(task_info: TaskInfo) -> Task {
    Delay::new(Duration::from_secs(
        task_info.period.try_into().expect("Failed to convert i64 to u64"),
    ))
    .await;
    task_info.task
}

#[allow(unused)]
pub struct Peer<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Unique ID of the peer
    id: PeerId,

    /// Inbound/outbound
    pub(super) role: PeerRole,

    /// Current state of the peer (handshaking, listening, etc.)
    pub(super) state: PeerState,

    /// Channel for sending messages to `NetworkManager`
    mgr_tx: tokio::sync::mpsc::Sender<PeerEvent>,

    /// Channel for reading events from the `NetworkManager`
    mgr_rx: tokio::sync::mpsc::Receiver<Event>,

    /// Socket of the peer
    pub(super) socket: NetworkingBackend::Socket,

    /// Chain config
    pub(super) config: Arc<ChainConfig>,

    /// Last time when something was read from the socket
    pub(super) last_activity: i64,
}

#[allow(unused)]
impl<NetworkingBackend> Peer<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Create new peer
    ///
    /// # Arguments
    /// `id` - unique ID of the peer
    /// `role` - role (inbound/outbound) of the peer
    /// `config` - pointer to ChainConfig
    /// `socket` - socket for the peer
    /// `mgr_tx` - channel for sending messages to P2P
    /// `mgr_rx` - channel fro receiving messages from P2P
    pub fn new(
        id: PeerId,
        role: PeerRole,
        config: Arc<ChainConfig>,
        socket: NetworkingBackend::Socket,
        mgr_tx: tokio::sync::mpsc::Sender<PeerEvent>,
        mgr_rx: tokio::sync::mpsc::Receiver<Event>,
    ) -> Self {
        let state = match role {
            PeerRole::Outbound => {
                PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
            }
            PeerRole::Inbound => PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation,
            )),
        };

        Self {
            id,
            role,
            state,
            mgr_tx,
            mgr_rx,
            socket,
            config,
            last_activity: 0i64,
        }
    }

    /// Handle inbound message when local peer is listening
    async fn on_listening_state_peer_event(
        &mut self,
        state: ListeningState,
        msg: Message,
    ) -> error::Result<()> {
        match msg.msg {
            MessageType::Connectivity(msg) => {
                // found in src/proto/connectivity.rs
                self.on_inbound_connectivity_event(state, msg).await
            }
            MessageType::Handshake(_) => {
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }

    /// Handle message coming from the remote peer
    ///
    /// This might be an invalid message (such as a stray Hello), it might be Ping in
    /// which case we must respond with Pong, or it may be, e.g., GetHeaders in which
    /// case the message is sent to the P2P object for further processing
    pub(super) async fn on_peer_event(&mut self, msg: error::Result<Message>) -> error::Result<()> {
        // if `msg` contains an error, it means that there was a socket error,
        // i.e., remote peer closed the connection. Exit from the peer event loop
        //
        // Based on whether the handshake is in process or not, either a `SocketError`
        // or `ProtocolError` is returned
        let msg = msg.map_err(|err| match self.state {
            PeerState::Handshaking(_) => P2pError::ProtocolError(ProtocolError::Incompatible),
            _ => err,
        })?;

        if msg.magic != *self.config.magic_bytes() {
            return Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork));
        }

        match self.state {
            PeerState::Handshaking(state) => self.on_handshake_state_peer_event(state, msg).await,
            PeerState::Listening(state) => self.on_listening_state_peer_event(state, msg).await,
        }
    }

    /// Handle event coming from the network manager
    ///
    /// This might be a request the local node must make to remote peer, e.g. GetHeaders,
    /// it might be the response to request the remote peer sent us, or it might be
    /// a shutdown signal which instructs us to close the connection and exit the event loop
    async fn on_manager_event(&mut self, event: Option<Event>) -> error::Result<()> {
        todo!();
    }

    /// Handle timer event when local peer is listening
    async fn on_listening_state_timer_event(
        &mut self,
        state: ListeningState,
        task: Task,
    ) -> error::Result<Option<TaskInfo>> {
        match task {
            Task::Connectivity(task) => {
                // found in src/proto/connectivity.rs
                self.on_outbound_connectivity_event(state, task).await
            }
        }
    }

    /// Handle event that's scheduled to happen when a timer expires
    ///
    /// This might be a Ping message that is sent periodically to verify that
    /// the connection is open or, e.g., some one-shot task that has been schduled
    /// as a result of an incoming event from network manager/peer.
    ///
    /// In case the scheduled code was one-shot type event, the function returns
    /// `None` to indicate that the task has been executed and no futher processing
    /// must be done. If the task on the other hand is, periodically scheduled event,
    /// the task information is returned as an `Option` to the caller so that it knows
    /// the reschedule the event.
    ///
    /// This design allows the peer event loop to wait onan arbitrary number of
    /// timer-based events, both scheduled and one-shot.
    pub(super) async fn on_timer_event(&mut self, task: Task) -> error::Result<Option<TaskInfo>> {
        match self.state {
            PeerState::Listening(state) => self.on_listening_state_timer_event(state, task).await,
            PeerState::Handshaking(_) => {
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }

    /// Start event loop for the peer
    ///
    /// This function polls events from the peer socket,
    /// handles them appropriately and passes the messages
    /// to the P2P. It also listens to messages from P2P
    /// and sends them to the connected remote peer
    ///
    /// This function has its own loop so it must not be polled by
    /// an upper-level event loop but a task must be spawned for it
    pub async fn run(&mut self) -> error::Result<()> {
        let mut tasks = FuturesUnordered::new();
        tasks.push(schedule_event(TaskInfo {
            task: Task::Connectivity(ConnectivityTask::Ping {
                period: PING_PERIOD,
            }),
            period: PING_PERIOD,
        }));

        // the protocol defines that the initiator of the communication, i.e., the outbound
        // peer, is responsible for sending the Hello message. This means that
        // before the actual event loop is started, if the local node is initiator,
        // it must first send the Hello message and only then proceed to responding
        // to incoming events from remote peer and the network manager
        if self.role == PeerRole::Outbound {
            self.on_peer_event(Ok(Message {
                magic: *self.config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::Hello {
                    version: *self.config.version(),
                    services: 0u32,
                    timestamp: time::get(),
                }),
            }))
            .await?;
        }

        loop {
            tokio::select! {
                event = self.socket.recv() => {
                    self.on_peer_event(event).await?;
                    self.last_activity = time::get();
                }
                event = self.mgr_rx.recv().fuse() => {
                    self.on_manager_event(event).await?;
                }
                task = tasks.select_next_some() => {
                    if let Some(info) = self.on_timer_event(task).await? {
                        tasks.push(schedule_event(info));
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;
    use common::chain::config;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_peer_new() {
        let config = Arc::new(config::create_mainnet());
        let addr: <MockService as NetworkService>::Address = "[::1]:11121".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let peer_fut = TcpStream::connect(addr);

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        assert!(server_res.is_ok());
        assert!(peer_res.is_ok());

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = Peer::<MockService>::new(
            1,
            PeerRole::Outbound,
            config.clone(),
            server_res.unwrap(),
            peer_tx,
            rx,
        );
    }
}

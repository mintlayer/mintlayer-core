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
use crate::error::{self, P2pError, ProtocolError};
use crate::event::{Event, PeerEvent};
use crate::message::{Message, MessageType};
use crate::net::{NetworkService, SocketService};
use common::chain::ChainConfig;
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use futures_timer::Delay;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub type PeerId = u64;
pub type TaskId = u64;

struct TaskInfo {
    task_id: TaskId,
    period: Duration,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PeerRole {
    Initiator,
    Responder,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initiate the handshake by sending Hello message
    Initiate,

    // Wait for Hello message. When received, send HelloAck
    WaitInitiation,

    /// Wait HelloAck
    WaitResponse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Peer is handshaking with the remote peer
    Handshaking(HandshakeState),

    /// Listen to incoming messages from remote peer
    Listening,
}

// Represents a task that will run independently of any incoming/outgoing event
// meaning the decision to run is built into the protocol and, for example, the
// network manager is not responsible for scheduling the execution of this event
const DUMMY_TASK_ID: TaskId = 1;
const DUMMY_PERIOD: Duration = Duration::from_secs(60);

async fn schedule_event(task_info: TaskInfo) -> TaskId {
    Delay::new(task_info.period).await;
    task_info.task_id
}

#[allow(unused)]
pub struct Peer<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Unique ID of the peer
    id: PeerId,

    /// Is peer the initiator or responder of the session
    role: PeerRole,

    /// Current state of the peer (handshaking, listening, etc.)
    state: PeerState,

    /// Channel for sending messages to `NetworkManager`
    mgr_tx: tokio::sync::mpsc::Sender<PeerEvent>,

    /// Channel for reading events from the `NetworkManager`
    mgr_rx: tokio::sync::mpsc::Receiver<Event>,

    /// Socket of the peer
    pub socket: NetworkingBackend::Socket,

    /// Chain config
    config: Arc<ChainConfig>,
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
    /// `socket` - socket for the peer
    pub fn new(
        id: PeerId,
        role: PeerRole,
        config: Arc<ChainConfig>,
        socket: NetworkingBackend::Socket,
        mgr_tx: tokio::sync::mpsc::Sender<PeerEvent>,
        mgr_rx: tokio::sync::mpsc::Receiver<Event>,
    ) -> Self {
        let state = match role {
            PeerRole::Initiator => PeerState::Handshaking(HandshakeState::Initiate),
            PeerRole::Responder => PeerState::Handshaking(HandshakeState::WaitInitiation),
        };

        Self {
            id,
            role,
            state,
            mgr_tx,
            mgr_rx,
            socket,
            config,
        }
    }

    /// Handle handshake event
    ///
    /// This might be any event related to handshaking but the two ways of getting
    /// into this function are calling it directly (initator starts handshaking)
    /// or receiving a handshake message (Hello, HelloAck) at any point during reception.
    ///
    /// This function makes sure that the peer's state and role are correct and if so,
    /// it acts appropriately (changes state and possibly sends a message). If the peer's state
    /// or role is incorrect, a protocol error is emitted and the connection must be closed.
    ///
    /// This function may return `P2pError::ProtocolError` which means that there was
    /// an invalid peer state/message combination or it may return `P2pError::SocketError`
    /// indicating that the remote peer closed the connection during handshaking.
    ///
    /// This function assumes that the magic number of the message has been verified
    /// and sender and the local node are using the same chain type (Mainnet, Testnet)
    async fn on_handshake_event(&mut self, msg: Message) -> error::Result<()> {
        match self.state {
            PeerState::Handshaking(ref state) => match (state, self.role, msg.msg) {
                (HandshakeState::Initiate, PeerRole::Initiator, MessageType::Hello { .. }) => {
                    self.socket.send(&msg).await?;
                    self.state = PeerState::Handshaking(HandshakeState::WaitResponse);
                }
                (
                    HandshakeState::WaitInitiation,
                    PeerRole::Responder,
                    MessageType::Hello { version, .. },
                ) => {
                    if version != *self.config.version() {
                        return Err(P2pError::ProtocolError(ProtocolError::InvalidVersion));
                    }

                    let msg = Message {
                        magic: *self.config.magic_bytes(),
                        msg: MessageType::HelloAck {
                            version: *self.config.version(),
                            services: 0u32,
                            timestamp: SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)?
                                .as_secs(),
                        },
                    };

                    self.socket.send(&msg).await?;
                    self.state = PeerState::Listening;
                }
                (
                    HandshakeState::WaitResponse,
                    PeerRole::Initiator,
                    MessageType::HelloAck { version, .. },
                ) => match *self.config.version() {
                    version => self.state = PeerState::Listening,
                    _ => return Err(P2pError::ProtocolError(ProtocolError::InvalidVersion)),
                },
                _ => return Err(P2pError::ProtocolError(ProtocolError::InvalidState)),
            },
            _ => return Err(P2pError::ProtocolError(ProtocolError::InvalidState)),
        }

        Ok(())
    }

    /// Handle message coming from the remote peer
    ///
    /// This might be an invalid message (such as a stray Hello), it might be Ping in
    /// which case we must respond with Pong, or it may be, e.g., GetHeaders in which
    /// case the message is sent to the P2P object for further processing
    async fn on_peer_event(&mut self, msg: error::Result<Message>) -> error::Result<()> {
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

        match (&msg.msg, &self.state) {
            (MessageType::Hello { .. } | MessageType::HelloAck { .. }, _)
            | (_, PeerState::Handshaking(_)) => {
                self.on_handshake_event(msg).await?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle event coming from the network manager
    ///
    /// This might be a request the local node must make to remote peer, e.g. GetHeaders,
    /// it might be the response to request the remote peer sent us, or it might be
    /// a shutdown signal which instructs us to close the connection and exit the event loop
    async fn on_manager_event(&mut self, event: Option<Event>) -> error::Result<()> {
        todo!();
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
    async fn on_timer_event(&mut self, task_id: TaskId) -> error::Result<Option<TaskInfo>> {
        todo!();
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
            task_id: DUMMY_TASK_ID,
            period: DUMMY_PERIOD,
        }));

        // the protocol defines that the initiator of the communication, i.e., the peer
        // who connected is responsible for sending the Hello message. This means that
        // before the actual event loop is started, if the local node is initiator,
        // it must first send the Hello message and only then proceed to responding
        // to incoming events from remote peer and the network manager
        if self.role == PeerRole::Initiator {
            self.on_handshake_event(Message {
                magic: *self.config.magic_bytes(),
                msg: MessageType::Hello {
                    version: *self.config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
                },
            })
            .await;
        }

        loop {
            tokio::select! {
                event = self.socket.recv() => {
                    self.on_peer_event(event).await?;
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
        let addr: <MockService as NetworkService>::Address = "[::1]:11111".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let peer_fut = TcpStream::connect(addr);

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        assert!(server_res.is_ok());
        assert!(peer_res.is_ok());

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = Peer::<MockService>::new(
            1,
            PeerRole::Initiator,
            config.clone(),
            server_res.unwrap(),
            peer_tx,
            rx,
        );
    }
}

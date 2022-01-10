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
use crate::message::{HandshakeMessage, Message, MessageType};
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum InboundHandshakeState {
    /// Wait for Hello message
    WaitInitiation,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum OutboundHandshakeState {
    /// Send Hello message
    Initiate,

    /// Wait for HelloAck message
    WaitResponse,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum HandshakeState {
    /// Handshake state for the inbound peer
    Inbound(InboundHandshakeState),

    /// Handshake state for the outbound peer
    Outbound(OutboundHandshakeState),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PeerState {
    /// Peer is handshaking with the remote peer
    Handshaking(HandshakeState),

    /// Listen to incoming messages from remote peer
    Listening,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PeerRole {
    /// Peer accepted a connection from remote
    Inbound,

    /// Peer initiated a connection to remote
    Outbound,
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

    /// Inbound/outbound
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
        }
    }

    /// Handle handshake event for inbound peer
    ///
    /// The inbound peer has only only one state in which the received Hello is parsed
    /// and if it's valid, the peer proceeds to listening further messages and if it's
    /// invalid, the connection is closed.
    ///
    /// If HelloAck is received instead, the connection is closed due to protocol error
    /// and `P2pError::ProtocolError` is returned.
    ///
    /// If remote closed the socket, indicating protocol error, `P2pError::SocketError`
    /// is returned
    async fn on_inbound_handshake_event(
        &mut self,
        state: InboundHandshakeState,
        msg: HandshakeMessage,
    ) -> error::Result<()> {
        match (state, msg) {
            (InboundHandshakeState::WaitInitiation, HandshakeMessage::Hello { version, .. }) => {
                if version != *self.config.version() {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidVersion));
                }

                let msg = Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                        version: *self.config.version(),
                        services: 0u32,
                        timestamp: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)?
                            .as_secs(),
                    }),
                };

                self.socket.send(&msg).await?;
                self.state = PeerState::Listening;
                Ok(())
            }
            (InboundHandshakeState::WaitInitiation, HandshakeMessage::HelloAck { .. }) => {
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }

    /// Handle handshake event for outbound peer
    ///
    /// The outbound peer has two states: the state where it sends the Hello message
    /// to remote peer and the state where the HelloAck is received and validated.
    /// If the HelloAck indicates that the peers are compatible, the outbound peer
    /// concludes the handshake and proceeds to listen to further messages from the peer.
    ///
    /// All other states are considered protocols errors and `P2pError::ProtocolError`
    /// is returned.
    ///
    /// If remote closed the socket, indicating a protocol error, `P2pError::SocketError`
    /// is returned
    async fn on_outbound_handshake_event(
        &mut self,
        state: OutboundHandshakeState,
        msg: HandshakeMessage,
    ) -> error::Result<()> {
        match (state, msg) {
            (OutboundHandshakeState::Initiate, HandshakeMessage::Hello { .. }) => {
                self.socket
                    .send(&Message {
                        magic: *self.config.magic_bytes(),
                        msg: MessageType::Handshake(msg),
                    })
                    .await?;
                self.state = PeerState::Handshaking(HandshakeState::Outbound(
                    OutboundHandshakeState::WaitResponse,
                ));
            }
            (OutboundHandshakeState::WaitResponse, HandshakeMessage::HelloAck { version, .. }) => {
                if version != *self.config.version() {
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                }

                self.state = PeerState::Listening;
            }
            (OutboundHandshakeState::WaitResponse, HandshakeMessage::Hello { .. }) => {
                return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
            }
            (OutboundHandshakeState::Initiate, HandshakeMessage::HelloAck { .. }) => {
                return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
            }
        }

        Ok(())
    }

    /// Handle handshake event
    ///
    /// Peer has an active handshake going on and it has received a handshake event from remote
    /// As the handshaking procedure is different based on the role of the peer, branch out
    /// to separate functions to handle handshaking based on whether peer is the inbound
    /// or outbound participant of the connection.
    ///
    /// This function may return `P2pError::ProtocolError` which means that there was
    /// an invalid peer state/message combination or it may return `P2pError::SocketError`
    /// indicating that the remote peer closed the connection during handshaking.
    ///
    /// This function assumes that the magic number of the message has been verified
    /// and sender and the local node are using the same chain type (Mainnet, Testnet)
    async fn on_handshake_event(
        &mut self,
        state: HandshakeState,
        msg: HandshakeMessage,
    ) -> error::Result<()> {
        match state {
            HandshakeState::Inbound(state) => self.on_inbound_handshake_event(state, msg).await,
            HandshakeState::Outbound(state) => self.on_outbound_handshake_event(state, msg).await,
        }
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

        if let (PeerState::Handshaking(state), MessageType::Handshake(msg)) = (self.state, msg.msg) {
            self.on_handshake_event(state, msg).await?;
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
        if self.role == PeerRole::Outbound {
            self.on_peer_event(Ok(Message {
                magic: *self.config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::Hello {
                    version: *self.config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
                }),
            }))
            .await?;
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
    use crate::net::mock::{MockService, MockSocket};
    use common::chain::config;
    use common::primitives::version::SemVer;
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

    async fn create_two_peers(
        local_config: Arc<ChainConfig>,
        remote_config: Arc<ChainConfig>,
        addr: std::net::SocketAddr,
    ) -> (Peer<MockService>, Peer<MockService>) {
        let mut server = MockService::new(addr).await.unwrap();
        let peer_fut = TcpStream::connect(addr);

        let (remote_res, local_res) = tokio::join!(server.accept(), peer_fut);
        let remote_res = remote_res.unwrap();
        let local_res = local_res.unwrap();

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let (_tx2, rx2) = tokio::sync::mpsc::channel(1);

        let local = Peer::<MockService>::new(
            1,
            PeerRole::Outbound,
            local_config.clone(),
            remote_res,
            peer_tx.clone(),
            rx,
        );

        let remote = Peer::<MockService>::new(
            2,
            PeerRole::Inbound,
            remote_config.clone(),
            MockSocket::new(local_res),
            peer_tx,
            rx2,
        );

        (local, remote)
    }

    // Test that compatible nodes are able to handshake successfully
    #[tokio::test]
    async fn test_handshake_success() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11122".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

        // verify initial state
        assert_eq!(local.role, PeerRole::Outbound);
        assert_eq!(remote.role, PeerRole::Inbound);
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        // send valid hello
        let res = local
            .on_handshake_event(
                HandshakeState::Outbound(OutboundHandshakeState::Initiate),
                HandshakeMessage::Hello {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                },
            )
            .await;

        // verify state and call result
        assert!(res.is_ok());
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(
                OutboundHandshakeState::WaitResponse
            ))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        // read responder socket and parse message
        let msg = remote.socket.recv().await;
        let res = remote.on_peer_event(msg).await;

        // verify state and call result
        assert!(res.is_ok());
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(
                OutboundHandshakeState::WaitResponse
            ))
        );
        assert_eq!(remote.state, PeerState::Listening);

        // read initiator socket and parse message
        let msg = local.socket.recv().await;
        let res = local.on_peer_event(msg).await;

        assert!(res.is_ok());
        assert_eq!(local.state, PeerState::Listening);
        assert_eq!(remote.state, PeerState::Listening);
    }

    // Test that invalid magic number closes the connection
    #[tokio::test]
    async fn test_handshake_invalid_magic() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11123".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

        // verify initial state
        assert_eq!(local.role, PeerRole::Outbound);
        assert_eq!(remote.role, PeerRole::Inbound);
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        // send valid hello with incompatible magic value
        local
            .socket
            .send(&Message {
                magic: [0xde, 0xad, 0xbe, 0xef],
                msg: MessageType::Handshake(HandshakeMessage::Hello {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            })
            .await
            .unwrap();

        // read responder socket and parse message
        let msg = remote.socket.recv().await;
        let res = remote.on_peer_event(msg).await;

        // verify that `res` is error and protocol error is reported
        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork))
        );

        // simulate remote node closing the connection and verify that
        // the read operation causes a protocol error to be returned
        drop(remote);
        let msg = local.socket.recv().await;
        let res = local.on_peer_event(msg).await;

        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::Incompatible))
        );
    }

    // Test that invalid version number closes the connection
    #[tokio::test]
    async fn test_handshake_invalid_version() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11124".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

        // verify initial state
        assert_eq!(local.role, PeerRole::Outbound);
        assert_eq!(remote.role, PeerRole::Inbound);
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        // send valid hello with incompatible version
        local
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::Hello {
                    version: SemVer::new(13, 37, 1338),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            })
            .await
            .unwrap();

        // read responder socket and parse message
        let msg = remote.socket.recv().await;
        let res = remote.on_peer_event(msg).await;

        // verify that `res` is error and protocol error is reported
        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::InvalidVersion))
        );

        // simulate remote node closing the connection and verify that
        // the read operation causes a protocol error to be returned
        drop(remote);
        let msg = local.socket.recv().await;
        let res = local.on_peer_event(msg).await;

        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::Incompatible))
        );
    }

    // Outbound sends Hello to an incompatible responder who responds anyway with HelloACk
    #[tokio::test]
    async fn test_handshake_invalid_ack_sent() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11125".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

        // verify initial state
        assert_eq!(local.role, PeerRole::Outbound);
        assert_eq!(remote.role, PeerRole::Inbound);
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        // send valid hello with incompatible version
        local
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::Hello {
                    version: SemVer::new(13, 37, 1338),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            })
            .await
            .unwrap();

        // read responder socket and parse message
        let msg = remote.socket.recv().await;
        let res = remote.on_peer_event(msg).await;

        // verify that `res` is error and protocol error is reported
        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::InvalidVersion))
        );

        // simulate remote node closing the connection and verify that
        // the received HelloAck is rejected as it should be
        drop(local);
        let msg = remote.socket.recv().await;
        let res = remote.on_peer_event(msg).await;
        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::Incompatible))
        );
    }

    // Outbound sends Hello but responder sends something other than HelloAck
    #[tokio::test]
    async fn test_handshake_ack_not_sent() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11126".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

        // verify initial state
        assert_eq!(local.role, PeerRole::Outbound);
        assert_eq!(remote.role, PeerRole::Inbound);
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        // send valid hello
        let res = local
            .on_handshake_event(
                HandshakeState::Outbound(OutboundHandshakeState::Initiate),
                HandshakeMessage::Hello {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                },
            )
            .await;

        // verify state and call result
        assert!(res.is_ok());
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(
                OutboundHandshakeState::WaitResponse
            ))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        remote
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::Hello {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            })
            .await
            .unwrap();

        // read initiator socket and parse message
        let msg = local.socket.recv().await;
        let res = local.on_peer_event(msg).await;

        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
        );
    }

    // Outbound doesn't start the connection by handshaking but sends something else
    #[tokio::test]
    async fn test_handshake_hello_not_sent() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11127".parse().unwrap();
        let (mut local, mut remote) = create_two_peers(config.clone(), config.clone(), addr).await;

        // verify initial state
        assert_eq!(local.role, PeerRole::Outbound);
        assert_eq!(remote.role, PeerRole::Inbound);
        assert_eq!(
            local.state,
            PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate))
        );
        assert_eq!(
            remote.state,
            PeerState::Handshaking(HandshakeState::Inbound(
                InboundHandshakeState::WaitInitiation
            ))
        );

        // send valid HelloAck but it's considered invalid because initiator is expected to send Hello
        local
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            })
            .await
            .unwrap();

        // read responder socket and parse message
        let msg = remote.socket.recv().await;
        let res = remote.on_peer_event(msg).await;

        // verify that `res` is error and protocol error is reported
        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
        );

        // simulate remote node closing the connection and verify that
        // the read operation causes a protocol error to be returned
        drop(remote);
        let msg = local.socket.recv().await;
        let res = local.on_peer_event(msg).await;

        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::Incompatible))
        );
    }

    // try to initiate with helloack
    #[tokio::test]
    async fn test_initiate_with_helloack() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11128".parse().unwrap();
        let (mut local, _) = create_two_peers(config.clone(), config.clone(), addr).await;

        local.role = PeerRole::Outbound;
        local.state =
            PeerState::Handshaking(HandshakeState::Outbound(OutboundHandshakeState::Initiate));

        let res = local
            .on_peer_event(Ok(Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            }))
            .await;

        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
        );
    }

    // outbound tried to initiate with helloack
    #[tokio::test]
    async fn test_inbound_reject_helloack() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11129".parse().unwrap();
        let (mut local, _) = create_two_peers(config.clone(), config.clone(), addr).await;

        local.role = PeerRole::Inbound;
        local.state = PeerState::Handshaking(HandshakeState::Inbound(
            InboundHandshakeState::WaitInitiation,
        ));

        let res = local
            .on_peer_event(Ok(Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            }))
            .await;

        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
        );
    }

    // inbound responded to hello with hello
    #[tokio::test]
    async fn test_outbound_reject_hello() {
        let config = Arc::new(config::create_mainnet());
        let addr = "[::1]:11130".parse().unwrap();
        let (mut local, _) = create_two_peers(config.clone(), config.clone(), addr).await;

        local.role = PeerRole::Outbound;
        local.state = PeerState::Handshaking(HandshakeState::Outbound(
            OutboundHandshakeState::WaitResponse,
        ));

        let res = local
            .on_peer_event(Ok(Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Handshake(HandshakeMessage::Hello {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }),
            }))
            .await;

        assert_eq!(
            res,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
        );
    }
}

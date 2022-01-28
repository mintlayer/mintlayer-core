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
    error::{self, P2pError, ProtocolError},
    message::{ConnectivityMessage, Message, MessageType},
    net::{NetworkService, SocketService},
    peer::*,
};
use common::primitives::time;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectivityState {
    PingSent {
        /// Selected nonce for the Ping
        nonce: u64,

        /// How many times the Ping has been resent
        retries: isize,
    },
    PongReceived,
}

impl<NetworkingBackend> Peer<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Respond to an incoming Ping with a Pong
    ///
    /// # Arguments
    /// `nonce` - nonce that was in the Ping message
    async fn on_inbound_ping_event(&mut self, nonce: u64) -> error::Result<()> {
        self.socket
            .send(&Message {
                magic: *self.config.magic_bytes(),
                msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce }),
            })
            .await
    }

    /// Handle incoming Pong event
    ///
    /// This might be a new Pong which is validated against the nonce the local peer
    /// sent in its Ping message and if they match, the local peer state is converted to
    /// `PongReceived` to indicate that the connectivity check was completed successfully.
    ///
    /// There is also the possibility that the remote peer sent the Pong multiple times
    /// for whatever reason and that Pong was received before the state was changed to
    /// `ListeningState::Any` so just ignore the Pong message in that case.
    ///
    /// # Arguments
    /// `state` - current connectivity state of local peer
    /// `sent_nonce` - nonce that was in the Ping message that the local peer sent
    async fn on_inbound_pong_event(
        &mut self,
        state: ConnectivityState,
        sent_nonce: u64,
    ) -> error::Result<()> {
        match state {
            ConnectivityState::PingSent { nonce, .. } => {
                if sent_nonce == nonce {
                    self.state = PeerState::Listening(ListeningState::Connectivity(
                        ConnectivityState::PongReceived,
                    ));
                }

                Ok(())
            }
            ConnectivityState::PongReceived => Ok(()),
        }
    }

    /// Handle incoming connectivity event
    ///
    /// Ping can be received at any point during reception so the value of `state` does not
    /// change the way the incoming Ping is processed and thus it's ignored
    ///
    /// Incoming Pong is can be considered valid only if the current substate is of type
    /// `ConnectivityState` and processing is handled in `on_inbound_pong_event()`.
    ///
    /// Remote peer can also sent a stray Pong message which is considered incorrect behaviour from
    /// the protocol's perspective but closing the connection may be too harsh so for now just ignore it.
    ///
    /// # Arguments
    /// `state` - current listening state of the local peer
    /// `msg` - connectivity message received from the remote peer
    pub async fn on_inbound_connectivity_event(
        &mut self,
        state: ListeningState,
        msg: ConnectivityMessage,
    ) -> error::Result<()> {
        match (state, msg) {
            (_, ConnectivityMessage::Ping { nonce }) => self.on_inbound_ping_event(nonce).await,
            (ListeningState::Connectivity(state), ConnectivityMessage::Pong { nonce }) => {
                self.on_inbound_pong_event(state, nonce).await
            }
            (ListeningState::Any, ConnectivityMessage::Pong { .. }) => {
                // Receiving a stray Pong message is invalid behaviour but closing the connection
                // would be an overraction so just exit early (TODO: adjust peer reputation?)
                Ok(())
            }
        }
    }

    /// Handle outbound Ping event
    ///
    /// Handling an outbound Ping event means that the 60 second timer for the Ping task
    /// has expired and the local peer checks whether it should send a Ping message to remote.
    /// If there has been no activity on the socket in the last 60 seconds, meaning local peer
    /// has not received anything from remote peer, it sends a Ping message and schedules a PingRetry
    /// task to be executed next and changes its own state to `ConnectivityState::PingSent` to indicate
    /// that a response to the sent Ping message is expected.
    ///
    /// # Arguments
    /// `state` - current listening state of the local peer
    /// `period` - how often is Ping scheduled to be sent (default: 60 seconds)
    ///
    /// # Panics
    /// The `panic!()` is added only for completeness. The logical flow of the connectivity check
    /// makes it impossible for the execution to ever reach `panic!()` as `ConnectivityTask::Ping`
    /// and `ConnectivityTask::PingRetry` are never simultaneously active and the act of completing
    /// `ConnectivityTask::PingRetry` changes the state to `ListeningState::Any` and schedules
    /// `ConnectivityTask::Ping` whereas reaching this function and actually sending the Ping message
    /// changes the state to `ListeningState::Connectivity` and schedules the `ConnectivityTask::PingRetry`
    /// to be executed next.
    async fn on_outbound_ping_event(
        &mut self,
        state: ListeningState,
        period: i64,
    ) -> error::Result<Option<TaskInfo>> {
        match state {
            ListeningState::Any => {
                if time::get() - self.last_activity < period {
                    return Ok(Some(TaskInfo {
                        task: Task::Connectivity(ConnectivityTask::Ping { period }),
                        period,
                    }));
                }

                let nonce: u64 = rand::random();
                self.socket
                    .send(&Message {
                        magic: *self.config.magic_bytes(),
                        msg: MessageType::Connectivity(ConnectivityMessage::Ping { nonce }),
                    })
                    .await?;

                self.state = PeerState::Listening(ListeningState::Connectivity(
                    ConnectivityState::PingSent { nonce, retries: 0 },
                ));

                Ok(Some(TaskInfo {
                    task: Task::Connectivity(ConnectivityTask::PingRetry {
                        max_retries: PING_MAX_RETRIES,
                    }),
                    period: PING_REPLY_PERIOD,
                }))
            }
            ListeningState::Connectivity(_) => {
                panic!("Cannot send Ping while another connecivity check is in progress");
            }
        }
    }

    /// Handle valid PingRetry event
    ///
    /// The processing flow of PingRetry depends on one condition:
    ///  - has the remote send the local peer a Pong message?
    ///
    /// If they have, the PingRetry task schedules the Ping task to happen again
    /// in 60 seconds and changes the state to `ListeningState::Any`.
    ///
    /// If a Pong has not been received, the execution checks if there still are
    /// more retries left and if so, it resends the Ping message and schedules
    /// itself again. If there are no more retries left, the code returns an
    /// error indicating that the remote peer is unresponsive.
    ///
    /// # Arguments
    /// `state` - current connecivity state of the local peer
    /// `max_retries` - number of times the Ping is resent
    async fn on_valid_ping_retry_event(
        &mut self,
        state: ConnectivityState,
        max_retries: isize,
    ) -> error::Result<Option<TaskInfo>> {
        match state {
            ConnectivityState::PongReceived => {
                self.state = PeerState::Listening(ListeningState::Any);

                Ok(Some(TaskInfo {
                    task: Task::Connectivity(ConnectivityTask::Ping {
                        period: PING_PERIOD,
                    }),
                    period: PING_PERIOD,
                }))
            }
            ConnectivityState::PingSent { nonce, retries } => {
                if retries >= max_retries {
                    return Err(P2pError::ProtocolError(ProtocolError::Unresponsive));
                }

                self.socket
                    .send(&Message {
                        magic: *self.config.magic_bytes(),
                        msg: MessageType::Connectivity(ConnectivityMessage::Ping { nonce }),
                    })
                    .await?;

                self.state = PeerState::Listening(ListeningState::Connectivity(
                    ConnectivityState::PingSent {
                        nonce,
                        retries: retries + 1,
                    },
                ));

                Ok(Some(TaskInfo {
                    task: Task::Connectivity(ConnectivityTask::PingRetry {
                        max_retries: PING_MAX_RETRIES,
                    }),
                    period: PING_REPLY_PERIOD,
                }))
            }
        }
    }

    /// Handle Ping retry event issued by an expired timer
    ///
    /// # Arguments
    /// `state` - current listening state of the local peer
    /// `max_retries` - number of times the Ping is resent
    ///
    /// # Panics
    /// The `panic!()` is added only for completeness. `ConnectivityTask::PingRetry` is the
    /// only logic flow that changes the state to `ListeningState::Any` and simultaneously
    /// schedules the `ConnectivityTask::Ping` to be executed next. These two tasks are never
    /// scheduled simultaneously so the in this function `panic!()` is unreachable.
    async fn on_ping_retry_event(
        &mut self,
        state: ListeningState,
        max_retries: isize,
    ) -> error::Result<Option<TaskInfo>> {
        match state {
            ListeningState::Connectivity(state) => {
                self.on_valid_ping_retry_event(state, max_retries).await
            }
            ListeningState::Any => {
                panic!("Ping cannot be resent if peer is not in connectivity state");
            }
        }
    }

    /// Handle scheduled, ping-related event
    ///
    /// `on_outbound_connectivity_event()` either handles `ConnectivityTask::Ping` which means that
    /// the 60 second timer has expired and `self.last_activity` must be checked. If the socket has
    /// had activity within the last minute, the ping task is scheduled again and code returns.
    ///
    /// If there has been no activity within the last minute, `ConnectivityMessage::Ping` is
    /// sent to remote and it must respond to it within 10 seconds. Before the code returns,
    /// it schedules a new `ConnectivityTask::PingRetry` task which expires in 10 seconds and checks
    /// if the response has been received. If not, and if this is the first, second or third time of
    /// sending the Ping message, it's sent again and the `ConnectivityTask::PingRetry` task is also
    /// scheduled again.
    ///
    /// If no response is heard after three retries (10 + 30 seconds), the code returns an error
    /// which indicates to the caller that remote is unresponsive and connection should be
    /// closed.
    ///
    /// If a response is heard, the check was successful, remote is responsive,
    /// and the original `ConnectivityTask::Ping` is again scheduled to happen in 60 seconds.
    pub async fn on_outbound_connectivity_event(
        &mut self,
        state: ListeningState,
        task: ConnectivityTask,
    ) -> error::Result<Option<TaskInfo>> {
        match task {
            ConnectivityTask::Ping { period } => self.on_outbound_ping_event(state, period).await,
            ConnectivityTask::PingRetry { max_retries } => {
                self.on_ping_retry_event(state, max_retries).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        message::HandshakeMessage,
        net::mock::{MockService, MockSocket},
        net::Event,
        peer::PeerRole,
        proto::handshake::{HandshakeState, OutboundHandshakeState},
    };
    use common::chain::{config, ChainConfig};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpStream;

    async fn create_two_peers(config: Arc<ChainConfig>) -> (Peer<MockService>, Peer<MockService>) {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut server = MockService::new(addr, &[], &[]).await.unwrap();
        let peer_fut = TcpStream::connect(addr);

        let (remote_res, local_res) = tokio::join!(server.poll_next(), peer_fut);
        let remote_res: Event<MockService> = remote_res.unwrap();
        let Event::IncomingConnection(remote_res) = remote_res;
        let local_res = local_res.unwrap();

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let (_tx2, rx2) = tokio::sync::mpsc::channel(1);

        let mut local = Peer::<MockService>::new(
            1,
            PeerRole::Outbound,
            config.clone(),
            remote_res,
            peer_tx.clone(),
            rx,
        );

        let mut remote = Peer::<MockService>::new(
            2,
            PeerRole::Inbound,
            config.clone(),
            MockSocket::new(local_res),
            peer_tx,
            rx2,
        );

        // handshake with remove
        local
            .on_handshake_event(
                HandshakeState::Outbound(OutboundHandshakeState::Initiate),
                HandshakeMessage::Hello {
                    version: *config.version(),
                    services: 0u32,
                    timestamp: time::get(),
                },
            )
            .await
            .unwrap();

        // respond to Hello with HelloAck
        let msg = remote.socket.recv().await;
        remote.on_peer_event(msg).await.unwrap();

        // read HelloAck and conclude handshake
        let msg = local.socket.recv().await;
        local.on_peer_event(msg).await.unwrap();

        (local, remote)
    }

    // helper function to retransmit Ping and verify peer state
    async fn ping_retry(peer: &mut Peer<MockService>, retries: isize) {
        // resend the ping `retries` times and verify on each iteration that local peer's state updates correctly
        for retry in 0..retries {
            // verify peer state
            if let PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PingSent { nonce: _, retries },
            )) = peer.state
            {
                assert_eq!(retries, retry);
            } else {
                unreachable!();
            }

            // manually trigger `PingRetry` event
            peer.on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();
        }
    }

    // send ping, respond with pong
    #[tokio::test]
    async fn test_valid_ping_pong() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // verify local state
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
        } else {
            unreachable!();
        }

        // read Ping and verify state of remote peer
        let msg = remote.socket.recv().await;
        remote.on_peer_event(msg).await.unwrap();
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // read Pong and verify state of local peer
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));
        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        // trigger PingRetry event manually and verify final state
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: 3isize,
            }))
            .await
            .unwrap();
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }

    // do not respond to ping at all
    #[tokio::test]
    async fn test_no_response() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // transmit Ping 3 times
        ping_retry(&mut local, PING_MAX_RETRIES).await;

        // verify that local peer considers remote unresponsive (as it should)
        assert_eq!(
            local
                .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                    max_retries: PING_MAX_RETRIES,
                }))
                .await,
            Err(P2pError::ProtocolError(ProtocolError::Unresponsive))
        );
    }

    // respond to ping on the first retry
    #[tokio::test]
    async fn test_late_response_on_1st_retry() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // transmit Ping onces
        ping_retry(&mut local, 1).await;

        // read Ping and verify state of remote peer
        let msg = remote.socket.recv().await;
        remote.on_peer_event(msg).await.unwrap();
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // read Pong and verify state of local peer
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));
        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        // trigger PingRetry event manually and verify final state
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: 3isize,
            }))
            .await
            .unwrap();
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }

    // respond to ping on the second retry
    #[tokio::test]
    async fn test_late_response_on_2nd_retry() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // transmit Ping onces
        ping_retry(&mut local, 2).await;

        // read Ping and verify state of remote peer
        let msg = remote.socket.recv().await;
        remote.on_peer_event(msg).await.unwrap();
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // read Pong and verify state of local peer
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));
        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        // trigger PingRetry event manually and verify final state
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: 3isize,
            }))
            .await
            .unwrap();
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }

    // respond to ping on the third and last retry
    #[tokio::test]
    async fn test_late_response_on_3rd_retry() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // transmit Ping onces
        ping_retry(&mut local, PING_MAX_RETRIES).await;

        // read Ping and verify state of remote peer
        let msg = remote.socket.recv().await;
        remote.on_peer_event(msg).await.unwrap();
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // read Pong and verify state of local peer
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));
        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        // trigger PingRetry event manually and verify final state
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: 3isize,
            }))
            .await
            .unwrap();
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }

    // respond to ping but with invalid nonce
    #[tokio::test]
    async fn test_send_pong_invalid_nonce() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // verify local state
        let nonce = if let PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PingSent { nonce, retries },
        )) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

        // resend the ping N times and respond to it each time with an invalid Pong
        for retry in 0..PING_MAX_RETRIES {
            // send Pong with invalid nonce
            remote
                .socket
                .send(&Message {
                    magic: *config.magic_bytes(),
                    msg: MessageType::Connectivity(ConnectivityMessage::Pong {
                        nonce: nonce.wrapping_add(1),
                    }),
                })
                .await
                .unwrap();

            // read Pong from socket and verify that state remains as `PingRetry`
            let msg = local.socket.recv().await;
            assert_eq!(local.on_peer_event(msg).await, Ok(()));

            if let PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PingSent { nonce: _, retries },
            )) = local.state
            {
                assert_eq!(retries, retry);
            } else {
                unreachable!();
            }

            // manually trigger `PingRetry` event
            local
                .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                    max_retries: PING_MAX_RETRIES,
                }))
                .await
                .unwrap();
        }

        // verify that local peer considers remote unresponsive (as it should)
        assert_eq!(
            local
                .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                    max_retries: PING_MAX_RETRIES,
                }))
                .await,
            Err(P2pError::ProtocolError(ProtocolError::Unresponsive))
        );
    }

    // respond to ping first with invalid nonce and then with valid nonce
    #[tokio::test]
    async fn test_send_pong_invalid_then_valid_nonce() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // verify local state
        let nonce = if let PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PingSent { nonce, retries },
        )) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

        // send Pong with invalid nonce
        remote
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Connectivity(ConnectivityMessage::Pong {
                    nonce: nonce.wrapping_add(1),
                }),
            })
            .await
            .unwrap();

        // read Pong from socket and verify that state remains as `PingRetry`
        // meaning that the Pong was rejected
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));

        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
        } else {
            unreachable!();
        }

        // manually trigger `PingRetry` event
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();

        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 1isize);
        } else {
            unreachable!();
        }

        // send Pong with valid nonce
        remote
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce }),
            })
            .await
            .unwrap();

        // read Pong from socket and verify that state has changed to `PongReceived`
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));
        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        // manually trigger `PingRetry` event and verify that has changed to `ListeningState::Any`
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }

    // respond to ping first with invalid nonce, then miss first and second retry
    // and then finally respond to the last retry with correct nonce
    #[tokio::test]
    async fn test_send_pong_invalid_nonce_late_response() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // verify local state
        let nonce = if let PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PingSent { nonce, retries },
        )) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

        // send Pong with invalid nonce
        remote
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Connectivity(ConnectivityMessage::Pong {
                    nonce: nonce.wrapping_add(1),
                }),
            })
            .await
            .unwrap();

        // read Pong from socket and verify that state remains as `PingRetry`
        // meaning that the Pong was rejected
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));

        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
        } else {
            unreachable!();
        }

        // transmit Ping onces
        ping_retry(&mut local, PING_MAX_RETRIES).await;

        // send Pong with valid nonce
        remote
            .socket
            .send(&Message {
                magic: *config.magic_bytes(),
                msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce }),
            })
            .await
            .unwrap();

        // read Pong from socket and verify that state has changed to `PongReceived`
        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));
        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        // manually trigger `PingRetry` event and verify that has changed to `ListeningState::Any`
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }

    // Simultaneously send ping messages and verify that both peers
    // conclude the connectivity check correctly by sending a pong with
    // correct nonce and expecing a pong with correct nonce back
    #[tokio::test]
    async fn test_simultaneous_ping() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // verify local state
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
        } else {
            unreachable!();
        };

        // send Ping
        remote
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // verify remote state
        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = remote.state
        {
            assert_eq!(retries, 0isize);
        } else {
            unreachable!();
        };

        // read remote peer's Ping from socket and respond with Pong
        // save local peer's Ping to a temporary variable
        let msg = local.socket.recv().await;
        let ping: Message = remote.socket.recv().await.unwrap();
        assert_eq!(local.on_peer_event(msg).await, Ok(()));

        // read Pong from socket and verify state
        let msg = remote.socket.recv().await;
        assert_eq!(remote.on_peer_event(msg).await, Ok(()));

        // verify local and remote states
        assert_eq!(
            remote.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        if let PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
            nonce: _,
            retries,
        })) = local.state
        {
            assert_eq!(retries, 0isize);
        } else {
            unreachable!();
        };

        // respond to local peer's Ping and read the response
        assert_eq!(remote.on_peer_event(Ok(ping)).await, Ok(()));

        let msg = local.socket.recv().await;
        assert_eq!(local.on_peer_event(msg).await, Ok(()));

        // once again verify local and remote states
        assert_eq!(
            remote.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        assert_eq!(
            local.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived
            ))
        );

        // manually trigger `PingRetry` event for local and remote
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();
        remote
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();

        // finally verify that both peers are back to listening the socket normally
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));
    }

    // Send Pong and then another Pong right after
    #[tokio::test]
    async fn test_duplicate_pong() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, mut remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        // send Ping
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        // verify local state
        let nonce = if let PeerState::Listening(ListeningState::Connectivity(
            ConnectivityState::PingSent { nonce, retries },
        )) = local.state
        {
            assert_eq!(retries, 0isize);
            nonce
        } else {
            unreachable!();
        };

        // send Pong two times and verify that it doens't cause an error
        // but only changes the local node state to `PongReceived`
        for _ in 0..2 {
            remote
                .socket
                .send(&Message {
                    magic: *config.magic_bytes(),
                    msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce }),
                })
                .await
                .unwrap();

            let msg = local.socket.recv().await;
            assert_eq!(local.on_peer_event(msg).await, Ok(()));
            assert_eq!(
                local.state,
                PeerState::Listening(ListeningState::Connectivity(
                    ConnectivityState::PongReceived
                ))
            );
        }

        // finally verify that the state is back to `ListeningState::Any`
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::PingRetry {
                max_retries: PING_MAX_RETRIES,
            }))
            .await
            .unwrap();
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }

    // Verify that recent activity on the socket cancels the schedule Ping
    #[tokio::test]
    async fn test_socket_activity() {
        let config = Arc::new(config::create_mainnet());
        let (mut local, remote) = create_two_peers(config.clone()).await;

        // verify that handshake was successful
        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
        assert_eq!(remote.state, PeerState::Listening(ListeningState::Any));

        local.last_activity = time::get();

        // try to send Ping and verify that because last activity on the socket was
        // less than 60 seconds ago, Ping is not sent
        local
            .on_timer_event(Task::Connectivity(ConnectivityTask::Ping { period: 60i64 }))
            .await
            .unwrap();

        assert_eq!(local.state, PeerState::Listening(ListeningState::Any));
    }
}

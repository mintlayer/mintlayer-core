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
use logging::log;

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
                    log::trace!("{:?}: pong received", self.id);
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
                log::warn!("{:?}: stray pong received", self.id);
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
                log::trace!("{:?}: send ping", self.id);

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
                    log::error!("{:?}: remote is unresponsive", self.id);
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
        net::mock::{MockService, MockSocket},
        peer::{ListeningState, PeerRole},
    };
    use common::chain::config;
    use std::sync::Arc;

    // make a mock service peer
    async fn make_peer() -> Peer<MockService> {
        let (peer_tx, _) = tokio::sync::mpsc::channel(1);
        let (sync_tx, _) = tokio::sync::mpsc::channel(1);
        let (_, rx) = tokio::sync::mpsc::channel(1);

        Peer::<MockService>::new(
            test_utils::get_mock_id(),
            PeerRole::Inbound,
            Arc::new(config::create_mainnet()),
            MockSocket::new(test_utils::get_tcp_socket().await),
            peer_tx,
            sync_tx,
            rx,
        )
    }

    // verify that an invalid listening state during ping retry event results in panic
    #[should_panic]
    #[tokio::test]
    async fn test_on_ping_retry_event() {
        make_peer()
            .await
            .on_ping_retry_event(ListeningState::Any, 0isize)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_on_valid_ping_retry_event() {
        let mut peer = make_peer().await;

        // verify that after too many retries
        // the remote peer is considered unresponsive
        assert_eq!(
            peer.on_valid_ping_retry_event(
                ConnectivityState::PingSent {
                    nonce: u64::MAX,
                    retries: 3isize,
                },
                1isize
            )
            .await,
            Err(P2pError::ProtocolError(ProtocolError::Unresponsive))
        );

        // verify state and returned task are updated accordingly
        assert_eq!(
            peer.on_valid_ping_retry_event(
                ConnectivityState::PingSent {
                    nonce: u64::MAX,
                    retries: 1isize,
                },
                3isize,
            )
            .await,
            Ok(Some(TaskInfo {
                task: Task::Connectivity(ConnectivityTask::PingRetry {
                    max_retries: PING_MAX_RETRIES,
                }),
                period: PING_REPLY_PERIOD,
            }))
        );
        assert_eq!(
            peer.state,
            PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
                nonce: u64::MAX,
                retries: 2,
            }))
        );

        // verify that the reception of pong converts the state to `Listening::Any`
        assert_eq!(
            peer.on_valid_ping_retry_event(ConnectivityState::PongReceived, 3isize,).await,
            Ok(Some(TaskInfo {
                task: Task::Connectivity(ConnectivityTask::Ping {
                    period: PING_PERIOD,
                }),
                period: PING_PERIOD,
            }))
        );
        assert_eq!(peer.state, PeerState::Listening(ListeningState::Any));
    }

    #[tokio::test]
    async fn test_outbound_ping_event() {
        let mut peer = make_peer().await;

        // verify that enough time has passed since the last activity
        // on the socket, Ping is sent and PingRetry task is scheduled
        peer.last_activity = time::get();

        assert_eq!(
            peer.on_outbound_ping_event(ListeningState::Any, 1337).await,
            Ok(Some(TaskInfo {
                task: Task::Connectivity(ConnectivityTask::Ping { period: 1337 }),
                period: 1337,
            }))
        );

        // verify that if it has been more than `PING_PERIOD` seconds since the
        // last ping was sent, it is sent again and PingRetry task is scheduled again
        peer.state = PeerState::Listening(ListeningState::Any);
        peer.last_activity = 0;

        assert_eq!(
            peer.on_outbound_ping_event(ListeningState::Any, PING_PERIOD).await,
            Ok(Some(TaskInfo {
                task: Task::Connectivity(ConnectivityTask::PingRetry {
                    max_retries: PING_MAX_RETRIES,
                }),
                period: PING_REPLY_PERIOD,
            }))
        );

        match peer.state {
            PeerState::Listening(ListeningState::Connectivity(ConnectivityState::PingSent {
                nonce: _,
                retries,
            })) => {
                assert_eq!(retries, 0);
            }
            _ => panic!("invalid state after ping has been sent"),
        }
    }

    #[should_panic]
    #[tokio::test]
    async fn test_outbound_ping_event_invalid_state() {
        make_peer()
            .await
            .on_outbound_ping_event(
                ListeningState::Connectivity(ConnectivityState::PingSent {
                    nonce: u64::MAX,
                    retries: 2,
                }),
                0i64,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_on_inbound_pong_event() {
        let mut peer = make_peer().await;

        // verify that pong with invalid nonce doesn't change state
        peer.state = PeerState::Listening(ListeningState::Any);
        assert_eq!(
            peer.on_inbound_pong_event(
                ConnectivityState::PingSent {
                    nonce: u64::MAX,
                    retries: 3isize
                },
                0u64
            )
            .await,
            Ok(())
        );
        assert_eq!(peer.state, PeerState::Listening(ListeningState::Any));

        // verify that valid pong changes the state to `PongReceived`
        assert_eq!(
            peer.on_inbound_pong_event(
                ConnectivityState::PingSent {
                    nonce: u64::MAX,
                    retries: 3isize
                },
                u64::MAX
            )
            .await,
            Ok(())
        );
        assert_eq!(
            peer.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived,
            ))
        );

        // verify that another pong keeps the state to `PongReceived`
        assert_eq!(
            peer.on_inbound_pong_event(ConnectivityState::PongReceived, u64::MAX).await,
            Ok(())
        );
        assert_eq!(
            peer.state,
            PeerState::Listening(ListeningState::Connectivity(
                ConnectivityState::PongReceived,
            ))
        );
    }
}

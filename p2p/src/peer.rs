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
use crate::error;
use crate::event::{Event, PeerEvent};
use crate::message::Message;
use crate::net::{NetworkService, SocketService};
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use futures_timer::Delay;
use std::time::Duration;

pub type PeerId = u128;
pub type TaskId = u128;

struct TaskInfo {
    task_id: TaskId,
    period: Duration,
}

// Represents a task that will run independently of any incoming/outgoing event
// meaning the decision to run is built into the protocol and, for example, the
// network manager is not responsible for scheduling the execution of this event
const DUMMY_TASK_ID: u128 = 1;
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
    peer_id: PeerId,

    /// Channel for sending messages to `NetworkManager`
    mgr_tx: tokio::sync::mpsc::Sender<PeerEvent>,

    /// Channel for reading events from the `NetworkManager`
    mgr_rx: tokio::sync::mpsc::Receiver<Event>,

    /// Socket of the peer
    pub socket: NetworkingBackend::Socket,
}

#[allow(unused)]
impl<NetworkingBackend> Peer<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Create new peer
    ///
    /// # Arguments
    /// `peer_id` - unique ID of the peer
    /// `socket` - socket for the peer
    pub fn new(
        peer_id: PeerId,
        socket: NetworkingBackend::Socket,
        mgr_tx: tokio::sync::mpsc::Sender<PeerEvent>,
        mgr_rx: tokio::sync::mpsc::Receiver<Event>,
    ) -> Self {
        Self {
            peer_id,
            mgr_tx,
            mgr_rx,
            socket,
        }
    }

    /// Handle message coming from the remote peer
    ///
    /// This might be an invalid message (such as a stray Hello), it might be Ping in
    /// which case we must respond with Pong, or it may be, e.g., GetHeaders in which
    /// case the message is sent to the P2P object for further processing
    async fn on_peer_event(&mut self, msg: error::Result<Message>) -> error::Result<()> {
        todo!();
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

        loop {
            tokio::select! {
                event = self.socket.recv() => {
                    self.on_peer_event(event).await?;
                }
                event = self.mgr_rx.recv().fuse() => {
                    self.on_manager_event(event).await?;
                }
                task = tasks.select_next_some().fuse() => {
                    self.on_timer_event(task).await?.map(|info| {
                        tasks.push(schedule_event(info));
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_peer_new() {
        let addr: <MockService as NetworkService>::Address = "[::1]:11111".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let peer_fut = TcpStream::connect(addr);

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        assert_eq!(server_res.is_ok(), true);
        assert_eq!(peer_res.is_ok(), true);

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = Peer::<MockService>::new(1u128, server_res.unwrap(), peer_tx, rx);
    }
}

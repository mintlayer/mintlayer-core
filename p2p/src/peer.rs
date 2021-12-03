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
use crate::event::Event;
use crate::net::{NetworkService, SocketService};
use futures::FutureExt;

pub type PeerId = u128;

#[allow(unused)]
pub struct Peer<NetworkingBackend: NetworkService> {
    /// Unique ID of the peer
    peer_id: PeerId,

    /// Channel for sending messages to `NetworkManager`
    mgr_tx: tokio::sync::mpsc::Sender<Event>,

    /// Channel for reading events from the `NetworkManager`
    mgr_rx: tokio::sync::mpsc::Receiver<Event>,

    /// Socket of the peer
    pub socket: NetworkingBackend::Socket,
}

#[allow(unused)]
impl<NetworkingBackend: NetworkService> Peer<NetworkingBackend> {
    /// Create new peer
    ///
    /// # Arguments
    /// `peer_id` - unique ID of the peer
    /// `socket` - socket for the peer
    pub fn new(
        peer_id: PeerId,
        socket: NetworkingBackend::Socket,
        mgr_tx: tokio::sync::mpsc::Sender<Event>,
        mgr_rx: tokio::sync::mpsc::Receiver<Event>,
    ) -> Self {
        Self {
            peer_id,
            mgr_tx,
            mgr_rx,
            socket,
        }
    }

    /// Start event loop for the peer
    ///
    /// This function polls events from the peer socket,
    /// handles them appropriately and passes the messages
    /// to the `NetworkManager`. It also listens to messages
    /// from `NetworkManager` and sends them to the connected
    /// peer
    ///
    /// This function has its own loop so it must not be polled by
    /// an upper-level event loop but a task must be spawned for it
    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                msg = self.socket.recv() => match msg {
                    Ok(v) => match v {
                        Event::Hello => todo!(),
                    }
                    Err(e) => {}
                },
                msg = self.mgr_rx.recv().fuse() => match msg {
                    Some(v) => match v {
                        Event::Hello => todo!(),
                    },
                    None => {}
                }
            }
        }
        Ok(())
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

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = Peer::<MockService>::new(1u128, server_res.unwrap(), tx, rx);
    }
}

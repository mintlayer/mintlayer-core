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
use crate::event::{Event, PeerEvent};
use crate::net::NetworkService;
use crate::peer::{Peer, PeerId};
use futures::FutureExt;
use rand::Rng;
use std::collections::HashMap;
use tokio::sync::mpsc::{Receiver, Sender};

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod peer;

const MANAGER_MAX_BACKLOG: usize = 256;
const PEER_MAX_BACKLOG: usize = 32;

#[allow(unused)]
pub enum ConnectivityEvent<T>
where
    T: NetworkService,
{
    Accept(error::Result<T::Socket>),
    Connect(T::Address),
}

#[allow(unused)]
struct P2P<NetworkingBackend> {
    network: NetworkingBackend,
    peers: HashMap<PeerId, Sender<Event>>,
    mgr_chan: (Sender<PeerEvent>, Receiver<PeerEvent>),
}

#[allow(unused)]
impl<NetworkingBackend> P2P<NetworkingBackend>
where
    NetworkingBackend: 'static + NetworkService,
{
    /// Create new P2P
    ///
    /// # Arguments
    /// `addr` - socket address where the local node binds itself to
    pub async fn new(addr: NetworkingBackend::Address) -> error::Result<Self> {
        Ok(Self {
            network: NetworkingBackend::new(addr).await?,
            peers: HashMap::new(),
            mgr_chan: tokio::sync::mpsc::channel(MANAGER_MAX_BACKLOG),
        })
    }

    /// Handle an event coming from peer
    ///
    /// This may be an incoming message from remote peer or it may be event
    /// notifying us that the remote peer has disconnected and P2P can destroy
    /// whatever peer context it is holding
    ///
    /// The event is wrapped in an `Option` because the peer might have ungracefully
    /// failed and reading from the closed channel might gives a `None` value, indicating
    /// a protocol on error which should be handled accordingly.
    async fn on_peer_event(&mut self, event: Option<PeerEvent>) -> error::Result<()> {
        todo!();
    }

    /// Handle a connectivity-related event
    ///
    /// This may be a socket event (new peer, `accept()` failed) or it may be
    /// a connection request from some other part of the system indicating that
    /// P2P should try to establish a connection with a specific remote peer.
    async fn on_connectivity_event(
        &mut self,
        event: ConnectivityEvent<NetworkingBackend>,
    ) -> error::Result<()> {
        match event {
            ConnectivityEvent::Accept(res) => res.map(|socket| self.create_peer(socket))?,
            ConnectivityEvent::Connect(address) => {
                self.network.connect(address).await.map(|socket| self.create_peer(socket))?
            }
        }

        Ok(())
    }

    /// Run the `P2P` event loop.
    ///
    /// This event loop has three responsibilities:
    ///  - accept incoming connections
    ///  - listen to messages from peers
    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                res = self.network.accept() => {
                    self.on_connectivity_event(ConnectivityEvent::Accept(res)).await?;
                },
                event = self.mgr_chan.1.recv().fuse() => {
                    self.on_peer_event(event).await?;
                }
            };
        }
    }

    /// Create `Peer` object from a socket object and spawn task for it
    fn create_peer(&mut self, socket: NetworkingBackend::Socket) {
        // find unique id for the peer
        let mut peer_id = rand::thread_rng().gen();

        while self.peers.contains_key(&peer_id) {
            peer_id = rand::thread_rng().gen();
        }

        let mgr_tx = self.mgr_chan.0.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(PEER_MAX_BACKLOG);
        self.peers.insert(peer_id, tx);

        tokio::spawn(async move {
            Peer::<NetworkingBackend>::new(peer_id, socket, mgr_tx, rx).run().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::mock::MockService;

    #[tokio::test]
    async fn test_p2p_new() {
        let addr: <MockService as NetworkService>::Address = "[::1]:8888".parse().unwrap();
        let res = P2P::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);

        // try to create new P2P object to the same address, should fail
        let addr: <MockService as NetworkService>::Address = "[::1]:8888".parse().unwrap();
        let res = P2P::<MockService>::new(addr).await;
        assert_eq!(res.is_err(), true);

        // try to create new P2P object to different address, should succeed
        let addr: <MockService as NetworkService>::Address = "127.0.0.1:8888".parse().unwrap();
        let res = P2P::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);
    }
}

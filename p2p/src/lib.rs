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
use crate::event::PeerEvent;
use crate::net::NetworkService;
use crate::peer::PeerId;
use futures::FutureExt;
use std::collections::HashMap;
use tokio::sync::mpsc::Sender;

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod peer;

const MANAGER_MAX_BACKLOG: usize = 256;

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
    peers: HashMap<PeerId, Sender<PeerEvent>>,
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
    async fn on_connecitivity_event(
        &mut self,
        event: ConnectivityEvent<NetworkingBackend>,
    ) -> error::Result<()> {
        todo!();
    }

    /// Run the `P2P` event loop.
    ///
    /// This event loop has three responsibilities:
    ///  - accept incoming connections
    ///  - listen to messages from peers
    pub async fn run(&mut self) -> error::Result<()> {
        let (mgr_tx, mut mgr_rx) = tokio::sync::mpsc::channel(MANAGER_MAX_BACKLOG);

        loop {
            tokio::select! {
                res = self.network.accept() => {
                    self.on_connecitivity_event(ConnectivityEvent::Accept(res)).await?;
                },
                event = mgr_rx.recv().fuse() => {
                    self.on_peer_event(event).await?;
                }
            };
        }
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

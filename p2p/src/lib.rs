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
use crate::event::Event;
use crate::net::NetworkService;
use crate::peer::PeerId;
use futures::FutureExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{Sender, Receiver};
use tokio::sync::Mutex;

pub mod error;
pub mod event;
pub mod net;
pub mod peer;

const MANAGER_MAX_BACKLOG: usize = 256;

#[allow(unused)]
struct NetworkManager<NetworkingBackend> {
    network: NetworkingBackend,
    peers: Arc<Mutex<HashMap<PeerId, Sender<Event>>>>,
}

#[allow(unused)]
impl<NetworkingBackend: 'static + NetworkService> NetworkManager<NetworkingBackend> {
    /// Create new NetworkManager
    ///
    /// # Arguments
    /// `addr` - socket address where the local node binds itself to
    pub async fn new(addr: NetworkingBackend::Address) -> error::Result<Self> {
        Ok(Self {
            network: NetworkingBackend::new(addr).await?,
            peers: Arc::new(Mutex::default()),
        })
    }

    /// Run the `NetworkManager` event loop.
    ///
    /// This event loop has three responsibilities:
    ///  - accept incoming connections
    ///  - listen to messages from peers
    ///  - listen to messages `P2P`
    ///
    /// It sends requests from peers to `P2P` which forwards them to
    /// the core service and when response for a request is received,
    /// `NetworkManager` forwards that to the correct peer.
    pub async fn run(&mut self) -> error::Result<()> {
        let (mgr_tx, mut mgr_rx): (Sender<Event>, Receiver<Event>) = tokio::sync::mpsc::channel(MANAGER_MAX_BACKLOG);

        loop {
            tokio::select! {
                conn = self.network.accept() => match conn {
                    Ok(socket) => todo!(),
                    Err(e) => {
                        eprintln!("accept() failed: {:#?}", e);
                        todo!();
                    }
                },
                msg = mgr_rx.recv().fuse() => match msg {
                    Some(v) => todo!(),
                    None => {
                        eprintln!("Received none from channel!");
                        todo!();
                    }
                }
            }
        }
    }
}

#[allow(unused)]
struct P2P<NetworkingBackend> {
    mgr: NetworkManager<NetworkingBackend>,
}

#[allow(unused)]
impl<NetworkingBackend: 'static + NetworkService> P2P<NetworkingBackend> {
    /// Create new P2P object
    ///
    /// # Arguments
    /// `addr` - socket address where the local node binds itself to
    pub async fn new(addr: NetworkingBackend::Address) -> error::Result<Self> {
        Ok(Self {
            mgr: NetworkManager::new(addr).await?,
        })
    }

    /// Start the networking subsystem
    ///
    /// This function starts the event loop for `NetworkManager`
    /// and in the future will listen incoming connections from
    /// the core service module.
    pub async fn run(&mut self) -> error::Result<()> {
        self.mgr.run().await
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

    #[tokio::test]
    async fn test_network_manager_new() {
        let addr: <MockService as NetworkService>::Address = "[::1]:1111".parse().unwrap();
        let res = NetworkManager::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);

        // try to create new NetworkManager to the same address, should fail
        let addr: <MockService as NetworkService>::Address = "[::1]:1111".parse().unwrap();
        let res = NetworkManager::<MockService>::new(addr).await;
        assert_eq!(res.is_err(), true);

        // try to create new NetworkManager to different address, should succeed
        let addr: <MockService as NetworkService>::Address = "127.0.0.1:1111".parse().unwrap();
        let res = NetworkManager::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);
    }
}

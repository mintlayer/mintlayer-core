// Copyright (c) 2021-2022 RBB S.r.l
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
#![cfg(not(loom))]

use crate::net::{ConnectivityService, FloodsubService, NetworkService};
use common::chain::ChainConfig;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod peer;
pub mod proto;
pub mod swarm;
pub mod sync;

#[allow(unused)]
pub struct P2P<T>
where
    T: NetworkService,
{
    /// Chain config
    config: Arc<ChainConfig>,

    /// TX channel for sending swarm control events
    tx_swarm: mpsc::Sender<event::SwarmControlEvent<T>>,
}

#[allow(unused)]
impl<T> P2P<T>
where
    T: 'static + NetworkService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::FloodsubHandle: FloodsubService<T>,
{
    /// Create new P2P
    ///
    /// # Arguments
    /// `addr` - socket address where the local node binds itself to
    pub async fn new(
        mgr_backlog: usize,
        peer_backlock: usize,
        addr: T::Address,
        config: Arc<ChainConfig>,
    ) -> error::Result<Self> {
        let (conn, flood) = T::start(addr, &[], &[]).await?;
        let (tx_swarm, rx_swarm) = mpsc::channel(16);
        let (tx_sync, rx_sync) = mpsc::channel(16);
        let (tx_peer, rx_peer) = mpsc::channel(16);

        let swarm_config = Arc::clone(&config);
        tokio::spawn(async move {
            let mut swarm = swarm::SwarmManager::<T>::new(
                swarm_config,
                conn,
                rx_swarm,
                tx_sync,
                tx_peer,
                mgr_backlog,
                peer_backlock,
            );
            let _ = swarm.run().await;
        });

        let sync_config = Arc::clone(&config);
        tokio::spawn(async move {
            let mut sync_mgr = sync::SyncManager::<T>::new(sync_config, flood, rx_sync, rx_peer);
            let _ = sync_mgr.run().await;
        });

        Ok(Self { config, tx_swarm })
    }

    /// Run the `P2P` event loop.
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting p2p event loop");

        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
}

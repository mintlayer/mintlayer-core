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
use crate::net::{ConnectivityService, NetworkService, PubSubService, SyncingService};
use common::chain::ChainConfig;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod pubsub;
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
    T::SyncingHandle: SyncingService<T>,
    T::PubSubHandle: PubSubService<T>,
{
    // TODO: think about channel sizes
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
        let (conn, flood, sync) = T::start(
            addr,
            &[],
            &[],
            Arc::clone(&config),
            std::time::Duration::from_secs(10),
        )
        .await?;
        let (tx_swarm, rx_swarm) = mpsc::channel(16);
        let (tx_sync, rx_sync) = mpsc::channel(16);

        let swarm_config = Arc::clone(&config);
        tokio::spawn(async move {
            let mut swarm = swarm::SwarmManager::<T>::new(swarm_config, conn, rx_swarm, tx_sync);
            let _ = swarm.run().await;
        });

        tokio::spawn(async move {
            let mut sync_mgr = sync::SyncManager::<T>::new(sync, rx_sync);
            let _ = sync_mgr.run().await;
        });

        tokio::spawn(async move {
            if let Err(e) = pubsub::PubSubManager::<T>::new(flood).run().await {
                todo!();
            }
            // let mut sync_mgr = ;
            // let _ = sync_mgr.run().await;
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

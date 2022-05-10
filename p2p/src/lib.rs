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
#![allow(unused)]

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

pub struct P2P<T>
where
    T: NetworkService,
{
    /// Chain config
    config: Arc<ChainConfig>,

    /// TX channel for sending swarm control events
    tx_swarm: mpsc::Sender<event::SwarmControlEvent<T>>,
}

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
        // let (tx_sync, rx_sync) = mpsc::channel(16);

        // let swarm_config = Arc::clone(&config);
        // tokio::spawn(async move {
        //     let mut swarm = swarm::SwarmManager::<T>::new(swarm_config, conn, rx_swarm, tx_sync);
        //     let _ = swarm.run().await;
        // });

        // tokio::spawn(async move {
        //     let mut sync_mgr = sync::SyncManager::<T>::new(sync, rx_sync);
        //     let _ = sync_mgr.run().await;
        // });

        // tokio::spawn(async move {
        //     if let Err(e) = pubsub::PubSubManager::<T>::new(
        //         flood,
        //         subsystem::Handle::new(
        //     ).run().await {
        //         todo!();
        //     }
        //     let mut sync_mgr = ;
        //     let _ = sync_mgr.run().await;
        // });

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::Libp2pService;
    use crate::pubsub::PubSubManager;
    use crate::swarm::SwarmManager;
    use common::chain::config;
    use libp2p::Multiaddr;
    use tokio::sync::mpsc;
    use crate::sync::SyncManager;

    #[tokio::test]
    async fn test_subsys_init() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let config = Arc::new(config::create_mainnet());
        let (conn, pubsub, sync) = Libp2pService::start(
            addr,
            &[],
            &[],
            Arc::clone(&config),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let storage = blockchain_storage::Store::new_empty().unwrap();
        let mut manager = subsystem::Manager::new("mintlayer");
        let consensus = manager.add_subsystem(
            "consensus",
            consensus::make_consensus(config::create_mainnet(), storage.clone()).unwrap(),
        );

		// NOTE: these channels are needed because `SwarmManager` must be able to call
		// `SyncManager` and `PubSubManager` and the managers cannot be initialized if
		// handles to them are acquired only after they are created.
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);

        let mut swarm_mgr = SwarmManager::<Libp2pService>::new(Arc::clone(&config), conn, rx1, tx2);
        let swarm_handle = manager.add_raw_subsystem("swarm", |call_rq, shut_rq| async move {
            swarm_mgr.run(call_rq, shut_rq).await
        });

        let mut pubsub_mgr = PubSubManager::<Libp2pService>::new(pubsub, consensus, swarm_handle.clone());
        let pubsub = manager.add_raw_subsystem("pubsub", |call_rq, shut_rq| async move {
            pubsub_mgr.run(call_rq, shut_rq).await
        });

        let mut sync_mgr = SyncManager::<Libp2pService>::new(sync, rx2, swarm_handle);
        let sync = manager.add_raw_subsystem("sync", |call_rq, shut_rq| async move {
            sync_mgr.run(call_rq, shut_rq).await
        });

        manager.main().await;
    }
}

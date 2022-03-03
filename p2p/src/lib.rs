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

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod peer;
pub mod proto;
pub mod swarm;

#[allow(unused)]
pub struct P2P<T>
where
    T: NetworkService,
{
    /// Chain config
    config: Arc<ChainConfig>,

    /// Handle for sending/receiving floodsub events
    flood: T::FloodsubHandle,
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
        let swarm_config = Arc::clone(&config);

        tokio::spawn(async move {
            let mut swarm =
                swarm::SwarmManager::<T>::new(swarm_config, conn, mgr_backlog, peer_backlock);
            let _ = swarm.run().await;
        });

        Ok(Self { config, flood })
    }

    /// Handle floodsub event
    fn on_floodsub_event(&mut self, event: net::FloodsubEvent<T>) -> error::Result<()> {
        let net::FloodsubEvent::MessageReceived {
            peer_id: _,
            topic,
            message,
        } = event;

        match topic {
            net::FloodsubTopic::Transactions => {
                log::debug!("received new transaction: {:#?}", message);
            }
            net::FloodsubTopic::Blocks => {
                log::debug!("received new block: {:#?}", message);
            }
        }

        Ok(())
    }

    /// Run the `P2P` event loop.
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting event loop");

        loop {
            tokio::select! {
                res = self.flood.poll_next() => {
                    res.map(|event| {
                        self.on_floodsub_event(event)
                    })?;
                }
            };
        }
    }
}

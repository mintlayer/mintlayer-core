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
use crate::{
    error::P2pError,
    net::{
        libp2p::Libp2pService, mock::MockService, ConnectivityService, NetworkService,
        PubSubService, SyncingService,
    },
};
use common::chain::block;
use common::chain::ChainConfig;
use consensus::consensus_interface;
use logging::log;
use std::{fmt::Debug, str::FromStr, sync::Arc};
use tokio::sync::mpsc;

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod pubsub;
pub mod rpc;
pub mod swarm;
pub mod sync;

pub struct P2pInterface<T: NetworkService> {
    p2p: P2P<T>,
}

impl<T> P2pInterface<T>
where
    T: NetworkService,
{
    pub async fn connect(&mut self, addr: String) -> error::Result<()>
    where
        <T as NetworkService>::Address: FromStr,
        <<T as NetworkService>::Address as FromStr>::Err: Debug,
    {
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::Connect(
                addr.parse::<T::Address>().map_err(|_| P2pError::InvalidAddress)?,
            ))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    pub async fn publish_block(&mut self, block: block::Block) -> error::Result<()> {
        self.p2p
            .tx_sync
            .send(event::SyncEvent::PublishBlock(block))
            .await
            .map_err(P2pError::from)
    }
}

#[allow(unused)]
struct P2P<T: NetworkService> {
    // TODO: add abstration for channels
    /// TX channel for sending swarm control events
    pub tx_swarm: mpsc::Sender<event::SwarmEvent<T>>,

    /// TX channel for sending syncing/pubsub events
    pub tx_sync: mpsc::Sender<event::SyncEvent>,
}

impl<T> P2P<T>
where
    T: 'static + NetworkService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingHandle: SyncingService<T>,
    T::PubSubHandle: PubSubService<T>,
{
    /// Start the P2P subsystem
    ///
    /// This function starts the networking backend and individual manager objects.
    pub async fn new(
        bind_addr: String,
        config: Arc<ChainConfig>,
        consensus: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
    ) -> error::Result<Self>
    where
        <T as NetworkService>::Address: FromStr,
        <<T as NetworkService>::Address as FromStr>::Err: Debug,
    {
        let (conn, flood, sync) = T::start(
            bind_addr.parse::<T::Address>().map_err(|_| P2pError::InvalidAddress)?,
            &[],
            &[net::PubSubTopic::Blocks],
            Arc::clone(&config),
            // TODO: get from config
            std::time::Duration::from_secs(10),
        )
        .await?;

        // TODO: think about these channel sizes
        let (tx_swarm, rx_swarm) = mpsc::channel(16);
        let (tx_p2p_sync, rx_p2p_sync) = mpsc::channel(16);
        let (tx_sync, rx_sync) = mpsc::channel(16);

        let swarm_config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = swarm::SwarmManager::<T>::new(swarm_config, conn, rx_swarm, tx_p2p_sync)
                .run()
                .await
            {
                log::error!("SwarmManager failed: {:?}", e);
            }
        });

        let sync_handle = consensus.clone();
        tokio::spawn(async move {
            if let Err(e) =
                sync::SyncManager::<T>::new(sync, sync_handle, rx_sync, rx_p2p_sync).run().await
            {
                log::error!("SyncManager failed: {:?}", e);
            }
        });

        // TODO: merge with syncmanager when appropriate
        tokio::spawn(async move {
            if let Err(e) = pubsub::PubSubManager::<T>::new(flood, consensus).run().await {
                log::error!("PubSubManager failed: {:?}", e);
            }
        });

        Ok(Self { tx_swarm, tx_sync })
    }
}

impl<T: NetworkService + 'static> subsystem::Subsystem for P2pInterface<T> {}

pub type P2pHandle<T> = subsystem::Handle<P2pInterface<T>>;

pub async fn make_p2p<T>(
    chain_config: Arc<ChainConfig>,
    consensus: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
    bind_addr: String,
) -> Result<P2pInterface<T>, P2pError>
where
    T: NetworkService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingHandle: SyncingService<T>,
    T::PubSubHandle: PubSubService<T>,
    <T as NetworkService>::Address: FromStr,
    <<T as NetworkService>::Address as FromStr>::Err: Debug,
{
    Ok(P2pInterface {
        p2p: P2P::new(bind_addr, chain_config, consensus).await?,
    })
}

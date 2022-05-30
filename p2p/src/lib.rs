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
        libp2p::Libp2pService, mock::MockService, ConnectivityService, NetworkingService,
        PubSubService, SyncingCodecService,
    },
};
use common::chain::block;
use common::chain::ChainConfig;
use consensus::consensus_interface;
use logging::log;
use std::{fmt::Debug, str::FromStr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod pubsub;
pub mod rpc;
pub mod swarm;
pub mod sync;

// TODO: figure out proper channel sizes
const CHANNEL_SIZE: usize = 64;

// TODO: this should come from a config
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct P2pInterface<T: NetworkingService> {
    p2p: P2P<T>,
}

// TODO: reduce code duplication?
impl<T> P2pInterface<T>
where
    T: NetworkingService,
{
    pub async fn connect(&mut self, addr: String) -> error::Result<()>
    where
        <T as NetworkingService>::Address: FromStr,
        <<T as NetworkingService>::Address as FromStr>::Err: Debug,
        <T as NetworkingService>::PeerId: FromStr,
        <<T as NetworkingService>::PeerId as FromStr>::Err: Debug,
    {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::Connect(
                addr.parse::<T::Address>().map_err(|_| P2pError::InvalidAddress)?,
                tx,
            ))
            .await
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    async fn disconnect(&self, peer_id: String) -> error::Result<()>
    where
        <T as NetworkingService>::PeerId: FromStr,
        <<T as NetworkingService>::PeerId as FromStr>::Err: Debug,
    {
        let (tx, rx) = oneshot::channel();
        let peer_id = peer_id.parse::<T::PeerId>().map_err(|_| P2pError::InvalidPeerId)?;

        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::Disconnect(peer_id, tx))
            .await
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    pub async fn get_peer_count(&self) -> error::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetPeerCount(tx))
            .await
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    pub async fn get_bind_address(&self) -> error::Result<String> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetBindAddress(tx))
            .await
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    pub async fn get_peer_id(&self) -> error::Result<String> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetPeerId(tx))
            .await
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    pub async fn get_connected_peers(&self) -> error::Result<Vec<String>> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetConnectedPeers(tx))
            .await
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }
}

#[allow(unused)]
struct P2P<T: NetworkingService> {
    // TODO: add abstration for channels
    /// TX channel for sending swarm control events
    pub tx_swarm: mpsc::Sender<event::SwarmEvent<T>>,

    /// TX channel for sending syncing/pubsub events
    pub tx_sync: mpsc::Sender<event::SyncEvent>,
}

impl<T> P2P<T>
where
    T: 'static + NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingCodecHandle: SyncingCodecService<T>,
    T::PubSubHandle: PubSubService<T>,
{
    /// Start the P2P subsystem
    ///
    /// This function starts the networking backend and individual manager objects.
    pub async fn new(
        bind_addr: String,
        config: Arc<ChainConfig>,
        consensus_handle: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
    ) -> error::Result<Self>
    where
        <T as NetworkingService>::Address: FromStr,
        <<T as NetworkingService>::Address as FromStr>::Err: Debug,
    {
        let (conn, pubsub, sync) = T::start(
            bind_addr.parse::<T::Address>().map_err(|_| P2pError::InvalidAddress)?,
            &[],
            &[net::PubSubTopic::Blocks],
            Arc::clone(&config),
            TIMEOUT,
        )
        .await?;

        // TODO: think about these channel sizes
        let (tx_swarm, rx_swarm) = mpsc::channel(CHANNEL_SIZE);
        let (tx_p2p_sync, rx_p2p_sync) = mpsc::channel(CHANNEL_SIZE);
        let (tx_sync, rx_sync) = mpsc::channel(CHANNEL_SIZE);
        let (tx_pubsub, rx_pubsub) = mpsc::channel(CHANNEL_SIZE);

        let swarm_config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = swarm::PeerManager::<T>::new(swarm_config, conn, rx_swarm, tx_p2p_sync)
                .run()
                .await
            {
                log::error!("PeerManager failed: {:?}", e);
            }
        });

        let sync_handle = consensus_handle.clone();
        let swarm_tx = tx_swarm.clone();
        let sync_config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = sync::SyncManager::<T>::new(
                sync_config,
                sync,
                sync_handle,
                rx_p2p_sync,
                swarm_tx,
                tx_pubsub,
            )
            .run()
            .await
            {
                log::error!("SyncManager failed: {:?}", e);
            }
        });

        // TODO: merge with syncmanager when appropriate
        tokio::spawn(async move {
            if let Err(e) =
                pubsub::PubSubMessageHandler::<T>::new(config, pubsub, consensus_handle, rx_pubsub)
                    .run()
                    .await
            {
                log::error!("PubSubMessageHandler failed: {:?}", e);
            }
        });

        Ok(Self { tx_swarm, tx_sync })
    }
}

impl<T: NetworkingService + 'static> subsystem::Subsystem for P2pInterface<T> {}

pub type P2pHandle<T> = subsystem::Handle<P2pInterface<T>>;

pub async fn make_p2p<T>(
    chain_config: Arc<ChainConfig>,
    consensus_handle: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
    bind_addr: String,
) -> Result<P2pInterface<T>, P2pError>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingCodecHandle: SyncingCodecService<T>,
    T::PubSubHandle: PubSubService<T>,
    <T as NetworkingService>::Address: FromStr,
    <<T as NetworkingService>::Address as FromStr>::Err: Debug,
    <T as NetworkingService>::PeerId: FromStr,
    <<T as NetworkingService>::PeerId as FromStr>::Err: Debug,
{
    Ok(P2pInterface {
        p2p: P2P::new(bind_addr, chain_config, consensus_handle).await?,
    })
}

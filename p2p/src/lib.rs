// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    config::P2pConfig,
    error::{ConversionError, P2pError},
    net::{ConnectivityService, NetworkingService, PubSubService, SyncingMessagingService},
};
use chainstate::chainstate_interface;
use common::chain::ChainConfig;
use logging::log;
use mempool::pool::MempoolInterface;
use std::{fmt::Debug, str::FromStr, sync::Arc};
use tap::TapFallible;
use tokio::sync::{mpsc, oneshot};

pub mod config;
pub mod constants;
pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod peer_manager;
pub mod rpc;
pub mod sync;

/// Result type with P2P errors
pub type Result<T> = core::result::Result<T, P2pError>;

pub struct P2pInterface<T: NetworkingService> {
    p2p: P2P<T>,
}

impl<T> P2pInterface<T>
where
    T: NetworkingService,
{
    pub async fn connect(&mut self, addr: String) -> crate::Result<()>
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
                addr.parse::<T::Address>().map_err(|_| {
                    P2pError::ConversionError(ConversionError::InvalidAddress(addr))
                })?,
                tx,
            ))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    async fn disconnect(&self, peer_id: String) -> crate::Result<()>
    where
        <T as NetworkingService>::PeerId: FromStr,
        <<T as NetworkingService>::PeerId as FromStr>::Err: Debug,
    {
        let (tx, rx) = oneshot::channel();
        let peer_id = peer_id
            .parse::<T::PeerId>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidPeerId(peer_id)))?;

        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::Disconnect(peer_id, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    pub async fn get_peer_count(&self) -> crate::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetPeerCount(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    pub async fn get_bind_address(&self) -> crate::Result<String> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetBindAddress(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    pub async fn get_peer_id(&self) -> crate::Result<String> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetPeerId(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    pub async fn get_connected_peers(&self) -> crate::Result<Vec<String>> {
        let (tx, rx) = oneshot::channel();
        self.p2p
            .tx_swarm
            .send(event::SwarmEvent::GetConnectedPeers(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }
}

struct P2P<T: NetworkingService> {
    // TODO: add abstration for channels
    /// TX channel for sending swarm control events
    pub tx_swarm: mpsc::UnboundedSender<event::SwarmEvent<T>>,

    /// TX channel for sending syncing/pubsub events
    pub _tx_sync: mpsc::UnboundedSender<event::SyncEvent>,
}

impl<T> P2P<T>
where
    T: 'static + NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::PubSubHandle: PubSubService<T>,
{
    /// Start the P2P subsystem
    ///
    /// This function starts the networking backend and individual manager objects.
    pub async fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        consensus_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
        _mempool_handle: subsystem::Handle<Box<dyn MempoolInterface>>,
    ) -> crate::Result<Self>
    where
        <T as NetworkingService>::Address: FromStr,
        <<T as NetworkingService>::Address as FromStr>::Err: Debug,
    {
        let p2p_config = Arc::new(p2p_config);
        let (conn, pubsub, sync) = T::start(
            p2p_config.bind_address.parse::<T::Address>().map_err(|_| {
                P2pError::ConversionError(ConversionError::InvalidAddress(
                    p2p_config.bind_address.clone(),
                ))
            })?,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
        )
        .await?;

        // P2P creates its components (such as PeerManager, sync, pubsub, etc) and makes
        // communications with them in two possible ways:
        //
        // 1. Fire-and-forget
        // 2. Request and wait for response
        //
        // The difference between these types is that enums that contain the events *can* have
        // a `oneshot::channel` object that must be used to send the response.
        let (tx_swarm, rx_swarm) = mpsc::unbounded_channel();
        let (tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
        let (_tx_sync, _rx_sync) = mpsc::unbounded_channel();

        {
            let chain_config = Arc::clone(&chain_config);
            tokio::spawn(async move {
                peer_manager::PeerManager::<T>::new(
                    chain_config,
                    Arc::clone(&p2p_config),
                    conn,
                    rx_swarm,
                    tx_p2p_sync,
                )
                .run()
                .await
                .tap_err(|err| log::error!("PeerManager failed: {err}"))
            });
        }
        {
            let consensus_handle = consensus_handle.clone();
            let tx_swarm = tx_swarm.clone();
            let chain_config = Arc::clone(&chain_config);

            tokio::spawn(async move {
                sync::BlockSyncManager::<T>::new(
                    chain_config,
                    sync,
                    consensus_handle,
                    rx_p2p_sync,
                    tx_swarm,
                    //tx_pubsub,
                )
                .run()
                .await
                .tap_err(|err| log::error!("SyncManager failed: {err}"))
            });
        }

        Ok(Self { tx_swarm, _tx_sync })
    }
}

impl<T: NetworkingService + 'static> subsystem::Subsystem for P2pInterface<T> {}

pub type P2pHandle<T> = subsystem::Handle<P2pInterface<T>>;

pub async fn make_p2p<T>(
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    consensus_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
    mempool_handle: subsystem::Handle<Box<dyn MempoolInterface>>,
) -> crate::Result<P2pInterface<T>>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::PubSubHandle: PubSubService<T>,
    <T as NetworkingService>::Address: FromStr,
    <<T as NetworkingService>::Address as FromStr>::Err: Debug,
    <T as NetworkingService>::PeerId: FromStr,
    <<T as NetworkingService>::PeerId as FromStr>::Err: Debug,
{
    Ok(P2pInterface {
        p2p: P2P::new(chain_config, p2p_config, consensus_handle, mempool_handle).await?,
    })
}

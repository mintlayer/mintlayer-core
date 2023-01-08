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

pub mod config;
pub mod constants;
pub mod error;
pub mod event;
pub mod interface;
pub mod message;
pub mod net;
pub mod peer_manager;
pub mod rpc;
pub mod sync;
#[cfg(feature = "testing_utils")]
pub mod testing_utils;

use std::{fmt::Debug, str::FromStr, sync::Arc};

use interface::p2p_interface::P2pInterface;
use tap::TapFallible;
use tokio::sync::mpsc;

use chainstate::chainstate_interface;
use common::chain::ChainConfig;
use logging::log;

use crate::{
    config::P2pConfig,
    error::{ConversionError, P2pError},
    event::{PeerManagerEvent, SyncEvent},
    net::{
        mock::{
            transport::{NoiseEncryptionAdapter, NoiseTcpTransport},
            MockService,
        },
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
};

/// Result type with P2P errors
pub type Result<T> = core::result::Result<T, P2pError>;

struct P2p<T: NetworkingService> {
    // TODO: add abstraction for channels
    /// A sender for the peer manager events.
    pub tx_peer_manager: mpsc::UnboundedSender<PeerManagerEvent<T>>,

    /// TX channel for sending syncing/pubsub events
    pub _tx_sync: mpsc::UnboundedSender<SyncEvent>,
}

impl<T> P2p<T>
where
    T: 'static + NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    /// Start the P2P subsystem
    ///
    /// This function starts the networking backend and individual manager objects.
    pub async fn new(
        transport: T::Transport,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
        _mempool_handle: mempool::MempoolHandle,
    ) -> Result<Self>
    where
        <T as NetworkingService>::Address: FromStr,
        <<T as NetworkingService>::Address as FromStr>::Err: Debug,
    {
        let (conn, sync) = T::start(
            transport,
            p2p_config.bind_address.parse::<T::Address>().map_err(|_| {
                P2pError::ConversionError(ConversionError::InvalidAddress(
                    p2p_config.bind_address.clone().into(),
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
        let (tx_peer_manager, rx_peer_manager) = mpsc::unbounded_channel();
        let (tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
        let (_tx_sync, _rx_sync) = mpsc::unbounded_channel();

        {
            let chain_config = Arc::clone(&chain_config);
            let p2p_config = Arc::clone(&p2p_config);
            tokio::spawn(async move {
                peer_manager::PeerManager::<T>::new(
                    chain_config,
                    p2p_config,
                    conn,
                    rx_peer_manager,
                    tx_p2p_sync,
                )
                .run()
                .await
                .tap_err(|err| log::error!("PeerManager failed: {err}"))
            });
        }
        {
            let chainstate_handle = chainstate_handle.clone();
            let tx_peer_manager = tx_peer_manager.clone();
            let chain_config = Arc::clone(&chain_config);

            tokio::spawn(async move {
                sync::BlockSyncManager::<T>::new(
                    chain_config,
                    p2p_config,
                    sync,
                    chainstate_handle,
                    rx_p2p_sync,
                    tx_peer_manager,
                )
                .run()
                .await
                .tap_err(|err| log::error!("SyncManager failed: {err}"))
            });
        }

        Ok(Self {
            tx_peer_manager,
            _tx_sync,
        })
    }
}

impl subsystem::Subsystem for Box<dyn P2pInterface> {}

pub type P2pHandle = subsystem::Handle<Box<dyn P2pInterface>>;

pub async fn make_p2p(
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
    mempool_handle: mempool::MempoolHandle,
) -> Result<Box<dyn P2pInterface>> {
    let stream_adapter = NoiseEncryptionAdapter::gen_new();
    let base_transport = net::mock::transport::TcpTransportSocket::new();
    let transport = NoiseTcpTransport::new(stream_adapter, base_transport);

    let p2p = P2p::<MockService<NoiseTcpTransport>>::new(
        transport,
        chain_config,
        p2p_config,
        chainstate_handle,
        mempool_handle,
    )
    .await?;

    Ok(Box::new(p2p))
}

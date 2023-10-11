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
pub mod error;
pub mod interface;
pub mod message;
pub mod net;
pub mod peer_manager;
pub mod protocol;
pub mod rpc;
pub mod sync;
pub mod testing_utils;
pub mod utils;

mod peer_manager_event;
#[cfg(test)]
mod tests;

use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use ::utils::atomics::SeqCstAtomicBool;
use ::utils::ensure;
use common::{
    chain::{config::ChainType, ChainConfig},
    time_getter::TimeGetter,
};
use interface::p2p_interface::P2pInterface;
use logging::log;
use mempool::MempoolHandle;
use net::default_backend::transport::{
    NoiseSocks5Transport, Socks5TransportSocket, TcpTransportSocket,
};
use peer_manager::peerdb::storage::PeerDbStorage;
use types::socket_address::SocketAddress;

use crate::{
    config::P2pConfig,
    error::{ConversionError, P2pError},
    net::{
        default_backend::{
            transport::{NoiseEncryptionAdapter, NoiseTcpTransport},
            DefaultNetworkingService,
        },
        ConnectivityService, MessagingService, NetworkingService, SyncingEventReceiver,
    },
};

pub use p2p_types as types;

pub use crate::{
    peer_manager_event::PeerManagerEvent,
    types::p2p_event::{P2pEvent, P2pEventHandler},
};

/// Result type with P2P errors
pub type Result<T> = core::result::Result<T, P2pError>;

struct P2p<T: NetworkingService> {
    /// A sender for the peer manager events.
    tx_peer_manager: mpsc::UnboundedSender<PeerManagerEvent>,
    mempool_handle: MempoolHandle,

    backend_shutdown_sender: oneshot::Sender<()>,

    // TODO: This flag is a workaround for graceful p2p termination.
    // See https://github.com/mintlayer/mintlayer-core/issues/888 for more details.
    shutdown: Arc<SeqCstAtomicBool>,

    backend_task: JoinHandle<()>,
    peer_manager_task: JoinHandle<()>,
    sync_manager_task: JoinHandle<()>,

    subscribers_sender: mpsc::UnboundedSender<P2pEventHandler>,

    _phantom: PhantomData<T>,
}

impl<T> P2p<T>
where
    T: 'static + NetworkingService + Send + Sync,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::MessagingHandle: MessagingService,
    T::SyncingEventReceiver: SyncingEventReceiver,
{
    /// Start the P2P subsystem
    ///
    /// This function starts the networking backend and individual manager objects.
    #[allow(clippy::too_many_arguments)]
    async fn new<S: PeerDbStorage + 'static>(
        transport: T::Transport,
        bind_addresses: Vec<SocketAddress>,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: chainstate::ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        peerdb_storage: S,
    ) -> Result<Self> {
        let shutdown = Arc::new(SeqCstAtomicBool::new(false));
        let (backend_shutdown_sender, shutdown_receiver) = oneshot::channel();
        let (subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();

        let (conn, messaging_handle, syncing_event_receiver, backend_task) = T::start(
            transport,
            bind_addresses,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            time_getter.clone(),
            Arc::clone(&shutdown),
            shutdown_receiver,
            subscribers_receiver,
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

        let peer_manager = peer_manager::PeerManager::<T, _>::new(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            conn,
            rx_peer_manager,
            time_getter.clone(),
            peerdb_storage,
        )?;
        let shutdown_ = Arc::clone(&shutdown);
        let peer_manager_task = logging::spawn_in_current_span(async move {
            match peer_manager.run().await {
                Ok(never) => match never {},
                // The channel can be closed during the shutdown process.
                Err(P2pError::ChannelClosed) if shutdown_.load() => {
                    log::info!("Peer manager is shut down");
                }
                Err(e) => {
                    shutdown_.store(true);
                    log::error!("Peer manager failed: {e:?}");
                }
            }
        });

        let sync_manager = sync::BlockSyncManager::<T>::new(
            chain_config,
            p2p_config,
            messaging_handle,
            syncing_event_receiver,
            chainstate_handle,
            mempool_handle.clone(),
            tx_peer_manager.clone(),
            time_getter,
        );
        let shutdown_ = Arc::clone(&shutdown);
        let sync_manager_task = logging::spawn_in_current_span(async move {
            match sync_manager.run().await {
                Ok(never) => match never {},
                // The channel can be closed during the shutdown process.
                Err(P2pError::ChannelClosed) if shutdown_.load() => {
                    log::info!("Sync manager is shut down");
                }
                Err(e) => {
                    shutdown_.store(true);
                    log::error!("Sync manager failed: {e:?}");
                }
            }
        });

        Ok(Self {
            tx_peer_manager,
            mempool_handle,
            shutdown,
            backend_shutdown_sender,
            backend_task,
            peer_manager_task,
            sync_manager_task,
            subscribers_sender,
            _phantom: PhantomData,
        })
    }
}

pub type P2pHandle = subsystem::Handle<dyn P2pInterface>;

pub type P2pNetworkingService = DefaultNetworkingService<NoiseTcpTransport>;
pub type P2pNetworkingServiceSocks5Proxy = DefaultNetworkingService<NoiseSocks5Transport>;
pub type P2pNetworkingServiceUnencrypted = DefaultNetworkingService<TcpTransportSocket>;

pub fn make_p2p_transport() -> NoiseTcpTransport {
    let stream_adapter = NoiseEncryptionAdapter::gen_new();
    let base_transport = TcpTransportSocket::new();
    NoiseTcpTransport::new(stream_adapter, base_transport)
}

pub fn make_p2p_transport_socks5_proxy(proxy: &str) -> NoiseSocks5Transport {
    let stream_adapter = NoiseEncryptionAdapter::gen_new();
    let base_transport = Socks5TransportSocket::new(proxy);
    NoiseSocks5Transport::new(stream_adapter, base_transport)
}

pub fn make_p2p_transport_unencrypted() -> TcpTransportSocket {
    TcpTransportSocket::new()
}

fn get_p2p_bind_addresses<S: AsRef<str>>(
    bind_addresses: &[S],
    p2p_port: u16,
    proxy_used: bool,
) -> Result<Vec<SocketAddress>> {
    if !bind_addresses.is_empty() {
        bind_addresses
            .iter()
            .map(|address| {
                address.as_ref().parse::<SocketAddress>().map_err(|_| {
                    P2pError::ConversionError(ConversionError::InvalidAddress(
                        address.as_ref().to_owned(),
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()
    } else if !proxy_used {
        // Bind to default addresses if none are specified by the user
        Ok(vec![
            SocketAddress::new(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), p2p_port)),
            SocketAddress::new(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), p2p_port)),
        ])
    } else {
        Ok(Vec::new())
    }
}

// TODO: Remove this structure.
// See https://github.com/mintlayer/mintlayer-core/issues/889 for more details.
pub struct P2pInit<S: PeerDbStorage + 'static> {
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate_handle: chainstate::ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    peerdb_storage: S,
    bind_addresses: Vec<SocketAddress>,
}

impl<S: PeerDbStorage + 'static> P2pInit<S> {
    async fn init<T>(self, transport: T::Transport) -> Result<P2p<T>>
    where
        T: 'static + NetworkingService + Send + Sync,
        T::ConnectivityHandle: ConnectivityService<T>,
        T::MessagingHandle: MessagingService,
        T::SyncingEventReceiver: SyncingEventReceiver,
    {
        P2p::<T>::new(
            transport,
            self.bind_addresses,
            self.chain_config,
            self.p2p_config,
            self.chainstate_handle,
            self.mempool_handle,
            self.time_getter,
            self.peerdb_storage,
        )
        .await
    }

    pub fn add_to_manager(self, name: &'static str, manager: &mut subsystem::Manager) -> P2pHandle {
        if let Some(true) = self.p2p_config.disable_noise {
            type NetService = P2pNetworkingServiceUnencrypted;
            assert_eq!(*self.chain_config.chain_type(), ChainType::Regtest);
            assert!(self.p2p_config.socks5_proxy.is_none());
            let transport = make_p2p_transport_unencrypted();
            manager.add_custom_subsystem(name, move |_| self.init::<NetService>(transport))
        } else if let Some(socks5_proxy) = &self.p2p_config.socks5_proxy {
            type NetService = P2pNetworkingServiceSocks5Proxy;
            let transport = make_p2p_transport_socks5_proxy(socks5_proxy);
            manager.add_custom_subsystem(name, move |_| self.init::<NetService>(transport))
        } else {
            type NetService = P2pNetworkingService;
            let transport = make_p2p_transport();
            manager.add_custom_subsystem(name, move |_| self.init::<NetService>(transport))
        }
    }
}

pub fn make_p2p<S: PeerDbStorage + 'static>(
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate_handle: chainstate::ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    peerdb_storage: S,
) -> Result<P2pInit<S>> {
    // Perform some early checks to prevent a failure in the run method.
    let bind_addresses = get_p2p_bind_addresses(
        &p2p_config.bind_addresses,
        chain_config.p2p_port(),
        p2p_config.socks5_proxy.is_some(),
    )?;

    if let Some(true) = p2p_config.disable_noise {
        ensure!(
            *chain_config.chain_type() == ChainType::Regtest,
            P2pError::InvalidConfigurationValue(
                "P2P encryption can only be disabled on the regtest network".to_owned()
            )
        );
        ensure!(
            p2p_config.socks5_proxy.is_none(),
            P2pError::InvalidConfigurationValue(
                "SOCKS5 proxy support is not implemented for unencrypted".to_owned()
            )
        );
    }

    Ok(P2pInit {
        chain_config,
        p2p_config,
        chainstate_handle,
        mempool_handle,
        time_getter,
        peerdb_storage,
        bind_addresses,
    })
}

#[async_trait::async_trait]
impl<T: NetworkingService> subsystem::Subsystem for P2p<T>
where
    T: 'static + NetworkingService + Send + Sync,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::MessagingHandle: MessagingService,
    T::SyncingEventReceiver: SyncingEventReceiver,
{
    type Interface = dyn P2pInterface;

    fn interface_ref(&self) -> &Self::Interface {
        self
    }

    fn interface_mut(&mut self) -> &mut Self::Interface {
        self
    }

    async fn shutdown(self) {
        self.shutdown.store(true);
        let _ = self.backend_shutdown_sender.send(());

        // Wait for the tasks to shut down.
        futures::future::join_all([
            self.backend_task,
            self.peer_manager_task,
            self.sync_manager_task,
        ])
        .await;
    }
}

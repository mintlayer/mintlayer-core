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
pub mod types;
pub mod utils;

mod run_p2p;

mod p2p_event;
mod peer_manager_event;

pub use crate::{
    p2p_event::{P2pEvent, P2pEventHandler},
    peer_manager_event::PeerManagerEvent,
};

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

// use tokio::{
//     sync::{mpsc, oneshot},
//     task::JoinHandle,
// };

use interface::p2p_interface::P2pInterface;
use net::default_backend::transport::{
    NoiseSocks5Transport, Socks5TransportSocket, TcpTransportSocket,
};
use peer_manager::peerdb::storage::PeerDbStorage;
use subsystem::{CallRequest, ShutdownRequest};

use ::utils::ensure;
use chainstate::chainstate_interface;
use common::{
    chain::{config::ChainType, ChainConfig},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::MempoolHandle;

use crate::{
    config::P2pConfig,
    error::{ConversionError, P2pError},
    net::{
        default_backend::{
            transport::{NoiseEncryptionAdapter, NoiseTcpTransport},
            DefaultNetworkingService,
        },
        MessagingService, NetworkingService,
    },
};

/// Result type with P2P errors
pub type Result<T> = core::result::Result<T, P2pError>;

impl subsystem::Subsystem for Box<dyn P2pInterface> {}

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
) -> Result<Vec<SocketAddr>> {
    if !bind_addresses.is_empty() {
        bind_addresses
            .iter()
            .map(|address| {
                address
                    .as_ref()
                    .parse::<<P2pNetworkingService as NetworkingService>::Address>()
                    .map_err(|_| {
                        P2pError::ConversionError(ConversionError::InvalidAddress(
                            address.as_ref().to_owned(),
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()
    } else if !proxy_used {
        // Bind to default addresses if none are specified by the user
        Ok(vec![
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), p2p_port),
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), p2p_port),
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
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    peerdb_storage: S,
    bind_addresses: Vec<SocketAddr>,
}

impl<S: PeerDbStorage + 'static> P2pInit<S> {
    pub async fn run(self, call: CallRequest<dyn P2pInterface>, shutdown: ShutdownRequest) {
        if let Err(e) = run_p2p(
            self.chain_config,
            self.p2p_config,
            self.chainstate_handle,
            self.mempool_handle,
            self.time_getter,
            self.peerdb_storage,
            self.bind_addresses,
            call,
            shutdown,
        )
        .await
        {
            log::error!("Failed to run p2p: {e:?}");
        }
    }
}

pub fn make_p2p<S: PeerDbStorage + 'static>(
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
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

#[allow(clippy::too_many_arguments)]
async fn run_p2p<S: PeerDbStorage + 'static>(
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    peerdb_storage: S,
    bind_addresses: Vec<SocketAddr>,
    call: CallRequest<dyn P2pInterface>,
    mut shutdown: ShutdownRequest,
) -> Result<()> {
    if let Some(true) = p2p_config.disable_noise {
        assert_eq!(*chain_config.chain_type(), ChainType::Regtest);
        assert!(p2p_config.socks5_proxy.is_none());

        let transport = make_p2p_transport_unencrypted();

        let p2p_running = run_p2p::run_p2p::<P2pNetworkingServiceUnencrypted, S>(
            transport,
            bind_addresses,
            chain_config,
            p2p_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            peerdb_storage,
            call,
            shutdown.recv(),
        )
        .await?;
        p2p_running.await
    } else if let Some(socks5_proxy) = &p2p_config.socks5_proxy {
        let transport = make_p2p_transport_socks5_proxy(socks5_proxy);

        let p2p_running = run_p2p::run_p2p::<P2pNetworkingServiceSocks5Proxy, S>(
            transport,
            bind_addresses,
            chain_config,
            p2p_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            peerdb_storage,
            call,
            shutdown.recv(),
        )
        .await?;
        p2p_running.await
    } else {
        let transport = make_p2p_transport();

        let p2p_running = run_p2p::run_p2p::<P2pNetworkingService, S>(
            transport,
            bind_addresses,
            chain_config,
            p2p_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            peerdb_storage,
            call,
            shutdown.recv(),
        )
        .await?;
        p2p_running.await
    }
}

// Copyright (c) 2021-2023 RBB S.r.l
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

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use common::time_getter::TimeGetter;
use logging::log;
use networking::transport::{TransportListener, TransportSocket};
use p2p_types::socket_address::SocketAddress;
use utils::atomics::SeqCstAtomicBool;

use crate::{
    error::P2pError,
    net::NetworkingService,
    protocol::{ProtocolVersion, SupportedProtocolVersion},
    P2pConfig, P2pEventHandler,
};

use super::{backend::Backend, ConnectivityHandle, MessagingHandle, SyncingEventReceiver};

// The preferred protocol version.
// Note that we intentionally keep this constant private, because most of the code should
// not depend on its value.
const PREFERRED_PROTOCOL_VERSION: SupportedProtocolVersion = SupportedProtocolVersion::V3;

// Some tests do need this value though in order to check the correct version selection.
// So we make it available for them via a function with a test-specific name and under cfg(test).
#[cfg(test)]
pub const fn get_preferred_protocol_version_for_tests() -> SupportedProtocolVersion {
    PREFERRED_PROTOCOL_VERSION
}

#[derive(Debug)]
pub struct DefaultNetworkingService<T: TransportSocket>(PhantomData<T>);

impl<T: TransportSocket> DefaultNetworkingService<T> {
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn start_generic(
        networking_enabled: bool,
        transport: <Self as NetworkingService>::Transport,
        socket: <T as TransportSocket>::Listener,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        time_getter: TimeGetter,
        shutdown: Arc<SeqCstAtomicBool>,
        shutdown_receiver: oneshot::Receiver<()>,
        subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
        protocol_version: ProtocolVersion,
        tracing_span: tracing::Span,
    ) -> crate::Result<(
        <Self as NetworkingService>::ConnectivityHandle,
        <Self as NetworkingService>::MessagingHandle,
        <Self as NetworkingService>::SyncingEventReceiver,
        JoinHandle<()>,
    )> {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let (conn_event_sender, conn_event_receiver) = mpsc::unbounded_channel();
        let (syncing_event_sender, syncing_event_receiver) = mpsc::unbounded_channel();
        let local_addresses = socket
            .local_addresses()
            .expect("to have bind address available")
            .into_iter()
            .map(SocketAddress::new)
            .collect();

        let backend = Backend::<T>::new(
            networking_enabled,
            transport,
            socket,
            chain_config,
            Arc::clone(&p2p_config),
            time_getter.clone(),
            cmd_receiver,
            conn_event_sender,
            syncing_event_sender,
            Arc::clone(&shutdown),
            shutdown_receiver,
            subscribers_receiver,
            protocol_version,
        );
        let backend_task = logging::spawn_in_span(
            async move {
                match backend.run().await {
                    Ok(never) => match never {},
                    Err(P2pError::ChannelClosed) if shutdown.load() => {
                        log::info!("Backend is shut down");
                    }
                    Err(e) => {
                        shutdown.store(true);
                        log::error!("Failed to run backend: {e}");
                    }
                }
            },
            tracing_span,
        );

        Ok((
            ConnectivityHandle::new(local_addresses, cmd_sender.clone(), conn_event_receiver),
            MessagingHandle::new(cmd_sender),
            SyncingEventReceiver {
                syncing_event_receiver,
            },
            backend_task,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_version(
        networking_enabled: bool,
        transport: <Self as NetworkingService>::Transport,
        bind_addresses: Vec<SocketAddress>,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        time_getter: TimeGetter,
        shutdown: Arc<SeqCstAtomicBool>,
        shutdown_receiver: oneshot::Receiver<()>,
        subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
        protocol_version: ProtocolVersion,
    ) -> crate::Result<(
        <Self as NetworkingService>::ConnectivityHandle,
        <Self as NetworkingService>::MessagingHandle,
        <Self as NetworkingService>::SyncingEventReceiver,
        JoinHandle<()>,
    )> {
        let bind_addresses = bind_addresses.iter().map(SocketAddress::socket_addr).collect();
        let socket = transport.bind(bind_addresses).await?;
        Self::start_generic(
            networking_enabled,
            transport,
            socket,
            chain_config,
            p2p_config,
            time_getter,
            shutdown,
            shutdown_receiver,
            subscribers_receiver,
            protocol_version,
            tracing::Span::current(),
        )
    }
}

#[async_trait]
impl<T: TransportSocket> NetworkingService for DefaultNetworkingService<T> {
    type Transport = T;
    type ConnectivityHandle = ConnectivityHandle<Self>;
    type MessagingHandle = MessagingHandle;
    type SyncingEventReceiver = SyncingEventReceiver;

    async fn start(
        networking_enabled: bool,
        transport: Self::Transport,
        bind_addresses: Vec<SocketAddress>,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        time_getter: TimeGetter,
        shutdown: Arc<SeqCstAtomicBool>,
        shutdown_receiver: oneshot::Receiver<()>,
        subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
    ) -> crate::Result<(
        Self::ConnectivityHandle,
        Self::MessagingHandle,
        Self::SyncingEventReceiver,
        JoinHandle<()>,
    )> {
        Self::start_with_version(
            networking_enabled,
            transport,
            bind_addresses,
            chain_config,
            p2p_config,
            time_getter,
            shutdown,
            shutdown_receiver,
            subscribers_receiver,
            PREFERRED_PROTOCOL_VERSION.into(),
        )
        .await
    }
}

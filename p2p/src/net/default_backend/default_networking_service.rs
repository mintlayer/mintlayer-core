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
use p2p_types::socket_address::SocketAddress;
use utils::atomics::SeqCstAtomicBool;

use crate::{
    error::P2pError,
    net::{
        default_backend::transport::{TransportListener, TransportSocket},
        NetworkingService,
    },
    protocol::{ProtocolVersion, SupportedProtocolVersion},
    P2pConfig, P2pEventHandler,
};

use super::{backend::Backend, ConnectivityHandle, MessagingHandle, SyncingEventReceiver};

// The preferred protocol version.
// Note that we intentionally keep this constant private, because most of the code should
// not depend on its value.
const PREFERRED_PROTOCOL_VERSION: SupportedProtocolVersion = SupportedProtocolVersion::V1;

// Some tests do need this value though in order to check the correct version selection.
// So we make it available for them via a function with a test-specific name and under cfg(test).
#[cfg(test)]
pub fn get_preferred_protocol_version_for_tests() -> SupportedProtocolVersion {
    PREFERRED_PROTOCOL_VERSION
}

#[derive(Debug)]
pub struct DefaultNetworkingService<T: TransportSocket>(PhantomData<T>);

impl<T: TransportSocket> DefaultNetworkingService<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_version(
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
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (conn_event_tx, conn_event_rx) = mpsc::unbounded_channel();
        let (syncing_event_tx, syncing_event_rx) = mpsc::unbounded_channel();
        let socket = transport.bind(bind_addresses).await?;
        let local_addresses = socket.local_addresses().expect("to have bind address available");

        let backend = Backend::<T>::new(
            transport,
            socket,
            chain_config,
            Arc::clone(&p2p_config),
            time_getter.clone(),
            cmd_rx,
            conn_event_tx,
            syncing_event_tx,
            Arc::clone(&shutdown),
            shutdown_receiver,
            subscribers_receiver,
            protocol_version,
        );
        let backend_task = logging::spawn_in_current_span(async move {
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
        });

        Ok((
            ConnectivityHandle::new(local_addresses, cmd_tx.clone(), conn_event_rx),
            MessagingHandle::new(cmd_tx),
            SyncingEventReceiver { syncing_event_rx },
            backend_task,
        ))
    }
}

#[async_trait]
impl<T: TransportSocket> NetworkingService for DefaultNetworkingService<T> {
    type Transport = T;
    type ConnectivityHandle = ConnectivityHandle<Self>;
    type MessagingHandle = MessagingHandle;
    type SyncingEventReceiver = SyncingEventReceiver;

    async fn start(
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

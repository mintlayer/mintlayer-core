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

pub mod backend;
pub mod peer;
pub mod transport;
pub mod types;

use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use logging::log;

use crate::{
    error::P2pError,
    error::ProtocolError,
    message::{PeerManagerMessage, SyncMessage},
    net::{
        default_backend::transport::{TransportListener, TransportSocket},
        types::{ConnectivityEvent, SyncingEvent},
        ConnectivityService, MessagingService, NetworkingService, SyncingEventReceiver,
    },
    types::peer_id::PeerId,
    P2pConfig, P2pEventHandler,
};

use super::types::services::Service;

#[derive(Debug)]
pub struct DefaultNetworkingService<T: TransportSocket>(PhantomData<T>);

#[derive(Debug)]
pub struct ConnectivityHandle<S: NetworkingService, T: TransportSocket> {
    /// The local addresses of a network service provider.
    local_addresses: Vec<S::Address>,

    /// TX channel for sending commands to default_backend backend
    cmd_tx: mpsc::UnboundedSender<types::Command<T::Address>>,

    /// RX channel for receiving connectivity events from default_backend backend
    conn_rx: mpsc::UnboundedReceiver<ConnectivityEvent<T::Address>>,

    _marker: PhantomData<fn() -> S>,
}

impl<S: NetworkingService, T: TransportSocket> ConnectivityHandle<S, T> {
    pub fn new(
        local_addresses: Vec<S::Address>,
        cmd_tx: mpsc::UnboundedSender<types::Command<T::Address>>,
        conn_rx: mpsc::UnboundedReceiver<ConnectivityEvent<T::Address>>,
    ) -> Self {
        Self {
            local_addresses,
            cmd_tx,
            conn_rx,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct MessagingHandle<T: TransportSocket> {
    command_sender: mpsc::UnboundedSender<types::Command<T::Address>>,
}

impl<T: TransportSocket> MessagingHandle<T> {
    pub fn new(command_sender: mpsc::UnboundedSender<types::Command<T::Address>>) -> Self {
        Self { command_sender }
    }
}

impl<T: TransportSocket> Clone for MessagingHandle<T> {
    fn clone(&self) -> Self {
        Self {
            command_sender: self.command_sender.clone(),
        }
    }
}

#[derive(Debug)]
pub struct SyncingReceiver {
    sync_rx: mpsc::UnboundedReceiver<SyncingEvent>,
}

#[async_trait]
impl<T: TransportSocket> NetworkingService for DefaultNetworkingService<T> {
    type Transport = T;
    type Address = T::Address;
    type BannableAddress = T::BannableAddress;
    type ConnectivityHandle = ConnectivityHandle<Self, T>;
    type MessagingHandle = MessagingHandle<T>;
    type SyncingEventReceiver = SyncingReceiver;

    async fn start(
        transport: Self::Transport,
        bind_addresses: Vec<Self::Address>,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        shutdown: Arc<AtomicBool>,
        shutdown_receiver: oneshot::Receiver<()>,
        subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
    ) -> crate::Result<(
        Self::ConnectivityHandle,
        Self::MessagingHandle,
        Self::SyncingEventReceiver,
        JoinHandle<()>,
    )> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (conn_tx, conn_rx) = mpsc::unbounded_channel();
        let (sync_tx, sync_rx) = mpsc::unbounded_channel();
        let socket = transport.bind(bind_addresses).await?;
        let local_addresses = socket.local_addresses().expect("to have bind address available");

        let p2p_config_ = Arc::clone(&p2p_config);
        let shutdown_ = Arc::clone(&shutdown);
        let backend_task = tokio::spawn(async move {
            let mut backend = backend::Backend::<T>::new(
                transport,
                socket,
                chain_config,
                p2p_config_,
                cmd_rx,
                conn_tx,
                sync_tx,
                shutdown_,
                shutdown_receiver,
                subscribers_receiver,
            );

            match backend.run().await {
                Ok(_) => unreachable!(),
                Err(P2pError::ChannelClosed) if shutdown.load(Ordering::SeqCst) => {
                    log::info!("Backend is shut down");
                }
                Err(e) => {
                    shutdown.store(true, Ordering::SeqCst);
                    log::error!("Failed to run backend: {e}");
                }
            }
        });

        Ok((
            ConnectivityHandle::new(local_addresses, cmd_tx.clone(), conn_rx),
            MessagingHandle::new(cmd_tx),
            Self::SyncingEventReceiver { sync_rx },
            backend_task,
        ))
    }
}

#[async_trait]
impl<S, T> ConnectivityService<S> for ConnectivityHandle<S, T>
where
    S: NetworkingService<Address = T::Address> + Send,
    T: TransportSocket,
{
    fn connect(&mut self, address: S::Address) -> crate::Result<()> {
        log::debug!(
            "try to establish outbound connection, address {:?}",
            address
        );

        self.cmd_tx.send(types::Command::Connect { address }).map_err(P2pError::from)
    }

    fn accept(&mut self, peer_id: PeerId) -> crate::Result<()> {
        log::debug!("accept new peer, peer_id: {peer_id}");

        self.cmd_tx.send(types::Command::Accept { peer_id }).map_err(P2pError::from)
    }

    fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        log::debug!("close connection with remote, peer_id: {peer_id}");

        self.cmd_tx.send(types::Command::Disconnect { peer_id }).map_err(P2pError::from)
    }

    fn send_message(&mut self, peer: PeerId, message: PeerManagerMessage) -> crate::Result<()> {
        self.cmd_tx
            .send(types::Command::SendMessage {
                peer,
                message: message.into(),
            })
            .map_err(Into::into)
    }

    fn local_addresses(&self) -> &[S::Address] {
        &self.local_addresses
    }

    async fn poll_next(&mut self) -> crate::Result<ConnectivityEvent<S::Address>> {
        self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

impl<T: TransportSocket> MessagingService for MessagingHandle<T> {
    fn send_message(&mut self, peer: PeerId, message: SyncMessage) -> crate::Result<()> {
        self.command_sender
            .send(types::Command::SendMessage {
                peer,
                message: message.into(),
            })
            .map_err(Into::into)
    }

    fn broadcast_message(&mut self, message: SyncMessage) -> crate::Result<()> {
        let service = match &message {
            SyncMessage::HeaderList(_) => Service::Blocks,
            SyncMessage::NewTransaction(_) => Service::Transactions,
            SyncMessage::HeaderListRequest(_)
            | SyncMessage::BlockListRequest(_)
            | SyncMessage::BlockResponse(_)
            | SyncMessage::TransactionRequest(_)
            | SyncMessage::TransactionResponse(_) => {
                return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                    format!("Unable to broadcast message: {message:?}"),
                )))
            }
        };

        self.command_sender
            .send(types::Command::AnnounceData {
                service,
                message: message.into(),
            })
            .map_err(P2pError::from)
    }
}

#[async_trait]
impl SyncingEventReceiver for SyncingReceiver {
    async fn poll_next(&mut self) -> crate::Result<SyncingEvent> {
        self.sync_rx.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests;

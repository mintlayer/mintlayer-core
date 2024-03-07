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
mod default_networking_service;
mod peer;
pub mod transport;
pub mod types;

use std::marker::PhantomData;

use async_trait::async_trait;
use tokio::sync::mpsc;

use logging::log;
use p2p_types::{services::Services, socket_address::SocketAddress};

use crate::{
    disconnection_reason::DisconnectionReason,
    error::P2pError,
    message::{BlockSyncMessage, PeerManagerMessage, TransactionSyncMessage},
    net::{
        self,
        types::{ConnectivityEvent, SyncingEvent},
        ConnectivityService, MessagingService, NetworkingService,
    },
    types::peer_id::PeerId,
};

pub use default_networking_service::DefaultNetworkingService;

#[derive(Debug)]
pub struct ConnectivityHandle<S: NetworkingService> {
    /// The local addresses of a network service provider.
    local_addresses: Vec<SocketAddress>,

    /// Channel sender for sending commands to Backend
    cmd_sender: mpsc::UnboundedSender<types::Command>,

    /// Channel receiver for receiving connectivity events from Backend
    conn_event_receiver: mpsc::UnboundedReceiver<ConnectivityEvent>,

    _marker: PhantomData<fn() -> S>,
}

impl<S: NetworkingService> ConnectivityHandle<S> {
    pub fn new(
        local_addresses: Vec<SocketAddress>,
        cmd_sender: mpsc::UnboundedSender<types::Command>,
        conn_event_receiver: mpsc::UnboundedReceiver<ConnectivityEvent>,
    ) -> Self {
        Self {
            local_addresses,
            cmd_sender,
            conn_event_receiver,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct MessagingHandle {
    command_sender: mpsc::UnboundedSender<types::Command>,
}

impl MessagingHandle {
    pub fn new(command_sender: mpsc::UnboundedSender<types::Command>) -> Self {
        Self { command_sender }
    }
}

impl Clone for MessagingHandle {
    fn clone(&self) -> Self {
        Self {
            command_sender: self.command_sender.clone(),
        }
    }
}

#[derive(Debug)]
pub struct SyncingEventReceiver {
    syncing_event_receiver: mpsc::UnboundedReceiver<SyncingEvent>,
}

#[async_trait]
impl<S> ConnectivityService<S> for ConnectivityHandle<S>
where
    S: NetworkingService + Send,
{
    fn connect(
        &mut self,
        address: SocketAddress,
        local_services_override: Option<Services>,
    ) -> crate::Result<()> {
        log::debug!(
            "try to establish outbound connection, address {:?}",
            address
        );

        Ok(self.cmd_sender.send(types::Command::Connect {
            address,
            local_services_override,
        })?)
    }

    fn accept(&mut self, peer_id: PeerId) -> crate::Result<()> {
        log::debug!("accept new peer, peer_id: {peer_id}");

        Ok(self.cmd_sender.send(types::Command::Accept { peer_id })?)
    }

    fn disconnect(
        &mut self,
        peer_id: PeerId,
        reason: Option<DisconnectionReason>,
    ) -> crate::Result<()> {
        log::debug!("close connection with remote, peer_id: {peer_id}");

        Ok(self.cmd_sender.send(types::Command::Disconnect { peer_id, reason })?)
    }

    fn send_message(&mut self, peer_id: PeerId, message: PeerManagerMessage) -> crate::Result<()> {
        Ok(self.cmd_sender.send(types::Command::SendMessage {
            peer_id,
            message: message.into(),
        })?)
    }

    fn local_addresses(&self) -> &[SocketAddress] {
        &self.local_addresses
    }

    async fn poll_next(&mut self) -> crate::Result<ConnectivityEvent> {
        self.conn_event_receiver.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

impl MessagingService for MessagingHandle {
    fn send_block_sync_message(
        &mut self,
        peer_id: PeerId,
        message: BlockSyncMessage,
    ) -> crate::Result<()> {
        Ok(self.command_sender.send(types::Command::SendMessage {
            peer_id,
            message: message.into(),
        })?)
    }

    fn send_transaction_sync_message(
        &mut self,
        peer_id: PeerId,
        message: TransactionSyncMessage,
    ) -> crate::Result<()> {
        Ok(self.command_sender.send(types::Command::SendMessage {
            peer_id,
            message: message.into(),
        })?)
    }
}

#[async_trait]
impl net::SyncingEventReceiver for SyncingEventReceiver {
    async fn poll_next(&mut self) -> crate::Result<SyncingEvent> {
        self.syncing_event_receiver.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests;

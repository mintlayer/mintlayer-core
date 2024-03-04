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

// Note: this module is more like "the_backend" rather than "default_backend". I.e. it cannot
// be replaced with some other "non-default" implementation, because its current implementation
// defines the protocol.
pub mod default_backend;
pub mod types;

use std::sync::Arc;

use async_trait::async_trait;
use common::time_getter::TimeGetter;
use p2p_types::{services::Services, socket_address::SocketAddress};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use utils::atomics::SeqCstAtomicBool;

use crate::{
    config,
    disconnection_reason::DisconnectionReason,
    message::{BlockSyncMessage, PeerManagerMessage, TransactionSyncMessage},
    types::peer_id::PeerId,
    P2pEventHandler,
};

/// [NetworkingService] provides the low-level network interface
/// that each network service provider must implement
#[async_trait]
pub trait NetworkingService {
    /// A generic networking transport.
    ///
    /// Can be used to initialize networking transport with authentication keys for example.
    type Transport;

    /// Handle for sending/receiving connectivity-related events
    type ConnectivityHandle: Send;

    /// A handle for sending messages and announcements to peers.
    type MessagingHandle: Send + Sync;

    /// A receiver for syncing events.
    type SyncingEventReceiver: Send;

    /// Initializes the network service provider.
    #[allow(clippy::too_many_arguments)]
    async fn start(
        transport: Self::Transport,
        bind_addresses: Vec<SocketAddress>,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
        time_getter: TimeGetter,
        shutdown: Arc<SeqCstAtomicBool>,
        shutdown_receiver: oneshot::Receiver<()>,
        subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
    ) -> crate::Result<(
        Self::ConnectivityHandle,
        Self::MessagingHandle,
        Self::SyncingEventReceiver,
        JoinHandle<()>,
    )>;
}

/// [ConnectivityService] provides an interface through which objects can send
/// and receive connectivity-related events to/from the network service provider
#[async_trait]
pub trait ConnectivityService<T>
where
    T: NetworkingService,
{
    /// Connect to a remote node
    ///
    /// This function doesn't block on the connection but returns immediately
    /// after dialing the remote peer. The connection success/failure event
    /// is returned through the [`ConnectivityService::poll_next()`] function.
    ///
    /// # Arguments
    /// `address` - socket address of the peer
    /// `local_services_override` - what services are enabled for the peer
    fn connect(
        &mut self,
        address: SocketAddress,
        local_services_override: Option<Services>,
    ) -> crate::Result<()>;

    /// Accept the peer as valid and allow reading of network messages
    fn accept(&mut self, peer_id: PeerId) -> crate::Result<()>;

    /// Disconnect active connection
    ///
    /// # Arguments
    /// `peer_id` - Peer ID of the remote node
    fn disconnect(
        &mut self,
        peer_id: PeerId,
        reason: Option<DisconnectionReason>,
    ) -> crate::Result<()>;

    /// Sends a message to the given peer.
    fn send_message(&mut self, peer: PeerId, message: PeerManagerMessage) -> crate::Result<()>;

    /// Return the socket addresses of the network service provider
    fn local_addresses(&self) -> &[SocketAddress];

    /// Poll events from the network service provider
    ///
    /// There are three types of events that can be received:
    /// - incoming peer connections
    /// - new discovered peers
    /// - peer expiration events
    async fn poll_next(&mut self) -> crate::Result<types::ConnectivityEvent>;
}

/// An interface for sending sync messages to peers.
pub trait MessagingService: Clone {
    /// Sends a block sync message to the peer.
    fn send_block_sync_message(
        &mut self,
        peer: PeerId,
        message: BlockSyncMessage,
    ) -> crate::Result<()>;

    /// Sends a transaction sync message to the peer.
    fn send_transaction_sync_message(
        &mut self,
        peer: PeerId,
        message: TransactionSyncMessage,
    ) -> crate::Result<()>;
}

#[async_trait]
pub trait SyncingEventReceiver {
    /// Polls syncing-related events from the networking service.
    async fn poll_next(&mut self) -> crate::Result<types::SyncingEvent>;
}

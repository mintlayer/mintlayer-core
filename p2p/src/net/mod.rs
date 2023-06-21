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

pub mod default_backend;
pub mod types;

use std::{fmt::Debug, hash::Hash, str::FromStr, sync::Arc};

use async_trait::async_trait;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use utils::atomics::SeqCstAtomicBool;

use crate::{
    config,
    message::{PeerManagerMessage, SyncMessage},
    types::peer_id::PeerId,
    P2pEventHandler,
};

use self::default_backend::transport::TransportAddress;

/// [NetworkingService] provides the low-level network interface
/// that each network service provider must implement
#[async_trait]
pub trait NetworkingService {
    /// A generic networking transport.
    ///
    /// Can be used to initialize networking transport with authentication keys for example.
    type Transport;

    /// A generic network address.
    ///
    /// Although the `Address` allows a fallible conversion to `BannableAddress`, a valid address
    /// must be able to be successfully converted into a bannable address.
    ///
    /// # Examples
    /// For an implementation built on `TcpListener`, the address format is:
    ///     `0.0.0.0:8888`
    type Address: Clone
        + Debug
        + Eq
        + Ord
        + Hash
        + Send
        + Sync
        + ToString
        + FromStr
        + TransportAddress
        + AsBannableAddress<BannableAddress = Self::BannableAddress>;

    /// An address type that can be banned.
    ///
    /// Usually it is part of the `NetworkingService::Address`. For example for a socket address
    /// that consists of an IP address and a port we want to ban the IP address.
    type BannableAddress: Debug + Eq + Ord + Send + ToString + FromStr;

    /// Handle for sending/receiving connectivity-related events
    type ConnectivityHandle: Send;

    /// A handle for sending messages and announcements to peers.
    type MessagingHandle: Send + Sync + Clone;

    /// A receiver for syncing events.
    type SyncingEventReceiver: Send;

    /// Initializes the network service provider.
    async fn start(
        transport: Self::Transport,
        bind_addresses: Vec<Self::Address>,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
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
    fn connect(&mut self, address: T::Address) -> crate::Result<()>;

    /// Accept the peer as valid and allow reading of network messages
    fn accept(&mut self, peer_id: PeerId) -> crate::Result<()>;

    /// Disconnect active connection
    ///
    /// # Arguments
    /// `peer_id` - Peer ID of the remote node
    fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()>;

    /// Sends a message to the given peer.
    fn send_message(&mut self, peer: PeerId, message: PeerManagerMessage) -> crate::Result<()>;

    /// Return the socket addresses of the network service provider
    fn local_addresses(&self) -> &[T::Address];

    /// Poll events from the network service provider
    ///
    /// There are three types of events that can be received:
    /// - incoming peer connections
    /// - new discovered peers
    /// - peer expiration events
    async fn poll_next(&mut self) -> crate::Result<types::ConnectivityEvent<T::Address>>;
}

/// An interface for sending messages and announcements to peers.
pub trait MessagingService: Clone {
    /// Sends a message to the peer.
    fn send_message(&mut self, peer: PeerId, message: SyncMessage) -> crate::Result<()>;

    /// Broadcasts a message to all peers.
    fn broadcast_message(&mut self, message: SyncMessage) -> crate::Result<()>;
}

#[async_trait]
pub trait SyncingEventReceiver {
    /// Polls syncing-related events from the networking service.
    async fn poll_next(&mut self) -> crate::Result<types::SyncingEvent>;
}

/// Extracts a bannable part from an address.
///
/// Usually we want to ban only a part of the address instead of the "whole" address. For example,
/// `SocketAddr` contains a port in addition to an IP address and we want to ban only the latter
/// one.
pub trait AsBannableAddress {
    type BannableAddress;

    /// Returns a bannable part of an address.
    fn as_bannable(&self) -> Self::BannableAddress;
}

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

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;

use crate::{
    config,
    message::{Announcement, PeerManagerMessage, SyncMessage},
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

    /// Unique ID assigned to a peer on the network
    type PeerId: Copy + Debug + Display + Eq + Ord + Hash + Send + Sync + ToString + FromStr;

    /// Handle for sending/receiving connectivity-related events
    type ConnectivityHandle: Send;

    /// Handle for sending/receiving request-response messages
    type SyncingMessagingHandle: Send;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `bind_addr` - socket address for incoming P2P traffic
    /// `chain_config` - chain config of the node
    async fn start(
        transport: Self::Transport,
        bind_addresses: Vec<Self::Address>,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
    ) -> crate::Result<(Self::ConnectivityHandle, Self::SyncingMessagingHandle)>;
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

    /// Disconnect active connection
    ///
    /// # Arguments
    /// `peer_id` - Peer ID of the remote node
    fn disconnect(&mut self, peer_id: T::PeerId) -> crate::Result<()>;

    /// Sends a message to the given peer.
    fn send_message(&mut self, peer: T::PeerId, message: PeerManagerMessage) -> crate::Result<()>;

    /// Return the socket addresses of the network service provider
    fn local_addresses(&self) -> &[T::Address];

    /// Poll events from the network service provider
    ///
    /// There are three types of events that can be received:
    /// - incoming peer connections
    /// - new discovered peers
    /// - peer expiration events
    async fn poll_next(&mut self) -> crate::Result<types::ConnectivityEvent<T>>;
}

/// [SyncingMessagingService] provides an interface for sending and receiving block
/// and header requests with a remote peer.
#[async_trait]
pub trait SyncingMessagingService<T>
where
    T: NetworkingService,
{
    /// Sends a message to the peer.
    fn send_message(&mut self, peer: T::PeerId, message: SyncMessage) -> crate::Result<()>;

    /// Publishes an announcement on the network.
    fn make_announcement(&mut self, announcement: Announcement) -> crate::Result<()>;

    /// Poll syncing-related event from the networking service
    async fn poll_next(&mut self) -> crate::Result<types::SyncingEvent<T>>;
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

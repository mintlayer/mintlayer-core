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

pub mod libp2p;
pub mod mock;
pub mod types;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;

use crate::{config, message, message::Announcement};

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
    ///
    /// For an implementation built on libp2p, the address format is:
    ///     `/ip4/0.0.0.0/tcp/8888/p2p/<peer ID>`
    type Address: Clone
        + Debug
        + Eq
        + Hash
        + Send
        + Sync
        + ToString
        + FromStr
        + AsBannableAddress<BannableAddress = Self::BannableAddress>
        + IsBannableAddress;

    /// An address type that can be banned.
    ///
    /// Usually it is part of the `NetworkingService::Address`. For example for a socket address
    /// that consists of an IP address and a port we want to ban the IP address.
    type BannableAddress: Debug + Eq + Ord + Send;

    /// Unique ID assigned to a peer on the network
    type PeerId: Copy + Debug + Display + Eq + Hash + Send + Sync + ToString + FromStr;

    /// Unique ID assigned to each received request from a peer
    type SyncingPeerRequestId: Copy + Debug + Eq + Hash + Send + Sync;

    /// Handle for sending/receiving connectivity-related events
    type ConnectivityHandle: Send;

    /// Handle for sending/receiving request-response messages
    type SyncingMessagingHandle: Send;

    /// Unique ID assigned to each pubsub message
    type SyncingMessageId: Clone + Debug + Send;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `bind_addr` - socket address for incoming P2P traffic
    /// `chain_config` - chain config of the node
    async fn start(
        transport: Self::Transport,
        bind_addr: Self::Address,
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
    async fn connect(&mut self, address: T::Address) -> crate::Result<()>;

    /// Disconnect active connection
    ///
    /// # Arguments
    /// `id` - socket address of the peer or peer id
    async fn disconnect(&mut self, id: DisconnectId<T::Address, T::PeerId>) -> crate::Result<()>;

    /// Return the socket address of the network service provider
    ///
    /// If the address isn't available yet, `None` is returned
    async fn local_addr(&self) -> crate::Result<Option<T::Address>>;

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
    /// Send block/header request to remote
    ///
    /// # Arguments
    /// * `peer_id` - Unique ID of the peer the request is sent to
    /// * `request` - Request to be sent
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        request: message::Request,
    ) -> crate::Result<T::SyncingPeerRequestId>;

    /// Send block/header response to remote
    ///
    /// # Arguments
    /// * `request_id` - ID of the request this is a response to
    /// * `message` - Response to be sent
    async fn send_response(
        &mut self,
        request_id: T::SyncingPeerRequestId,
        response: message::Response,
    ) -> crate::Result<()>;

    /// Publishes an announcement on the network.
    async fn make_announcement(&mut self, announcement: Announcement) -> crate::Result<()>;

    /// Reports a message validation result back to the backend.
    ///
    /// This function must be called as a result of an announcement processing.
    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        msg_id: T::SyncingMessageId,
        result: types::ValidationResult,
    ) -> crate::Result<()>;

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

// TODO: This is only needed because `libp2p::MultiAddr` can contain no IP address.
/// Checks if an address can be converted to bannable.
pub trait IsBannableAddress {
    fn is_bannable(&self) -> bool;
}

#[derive(Debug, Eq, PartialEq)]
pub enum DisconnectId<A, P> {
    Address(A),
    PeerId(P),
}

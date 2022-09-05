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
    sync::Arc,
};

use async_trait::async_trait;

use common::primitives;

use crate::{config, error, message};

/// [NetworkingService] provides the low-level network interface
/// that each network service provider must implement
#[async_trait]
pub trait NetworkingService {
    /// Generic socket address that the underlying implementation uses
    ///
    /// # Examples
    /// For an implementation built on `TcpListener`, the address format is:
    ///     `0.0.0.0:8888`
    ///
    /// For an implementation built on libp2p, the address format is:
    ///     `/ip4/0.0.0.0/tcp/8888/p2p/<peer ID>`
    type Address: Clone + Debug + Display + Eq + Hash + Send + Sync + ToString;

    /// Unique ID assigned to a peer on the network
    type PeerId: Copy + Debug + Display + Eq + Hash + Send + Sync + ToString;

    /// Unique ID assigned to each received request from a peer
    type SyncingPeerRequestId: Debug + Eq + Hash + Send + Sync;

    /// Handle for sending/receiving connecitivity-related events
    type ConnectivityHandle: Send;

    /// Handle for sending/receiving pubsub-related events
    type PubSubHandle: Send;

    /// Handle for sending/receiving request-response messages
    type SyncingMessagingHandle: Send;

    /// Unique ID assigned to each pubsub message
    type PubSubMessageId: Clone + Debug + Send;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `bind_addr` - socket address for incoming P2P traffic
    ///
    /// `strategies` - list of strategies that are used for peer discovery
    ///
    /// `chain_config` - chain config of the node
    ///
    /// `timeout` - timeout for outbound connections
    async fn start(
        bind_addr: Self::Address,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
    ) -> crate::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingMessagingHandle,
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
    /// This function doens't block on the connection but returns immediately
    /// after dialing the remote peer. The connection success/failure event
    /// is returned through the [`ConnectivityService::poll_next()`] function.
    ///
    /// # Arguments
    /// `address` - socket address of the peer
    async fn connect(&mut self, address: T::Address) -> crate::Result<()>;

    /// Disconnect active connection
    ///
    /// # Arguments
    /// `peer_id` - Peer ID of the remote node
    async fn disconnect(&mut self, peer_id: T::PeerId) -> crate::Result<()>;

    /// Return the socket address of the network service provider
    ///
    /// If the address isn't available yet, `None` is returned
    async fn local_addr(&self) -> crate::Result<Option<T::Address>>;

    /// Return peer id of the local node
    fn peer_id(&self) -> &T::PeerId;

    /// Ban peer
    async fn ban_peer(&mut self, peer_id: T::PeerId) -> crate::Result<()>;

    /// Poll events from the network service provider
    ///
    /// There are three types of events that can be received:
    /// - incoming peer connections
    /// - new discovered peers
    /// - peer expiration events
    async fn poll_next(&mut self) -> crate::Result<types::ConnectivityEvent<T>>;
}

/// [PubSubService] provides an interface through which objects can send
/// and receive pubsub-related events to/from the network service provider
#[async_trait]
pub trait PubSubService<T>
where
    T: NetworkingService,
{
    /// Publish a data announcement on the network
    ///
    /// # Arguments
    /// `announcement` - SCALE-encodable block or transaction
    async fn publish(&mut self, announcement: message::Announcement) -> crate::Result<()>;

    /// Report message validation result back to the backend
    ///
    /// # Arguments
    /// * `source` - source of the message
    /// * `msg_id` - unique ID of the message
    /// * `result` - result of validation, see [types::ValidationResult] for more details
    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        msg_id: T::PubSubMessageId,
        result: types::ValidationResult,
    ) -> crate::Result<()>;

    /// Subscribe to publish-subscribe topics
    ///
    /// # Arguments
    /// * `topics` - list of topics
    async fn subscribe(&mut self, topics: &[types::PubSubTopic]) -> crate::Result<()>;

    /// Poll unvalidated pubsub messages
    ///
    /// The message must be validated by the application layer and the validation
    /// result must reported using [PubSubService::report_validation_result].
    ///
    /// The message is not forwarded to any other peer before that function is called.
    async fn poll_next(&mut self) -> crate::Result<types::PubSubEvent<T>>;
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

    /// Poll syncing-related event from the networking service
    async fn poll_next(&mut self) -> crate::Result<types::SyncingEvent<T>>;
}

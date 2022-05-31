// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use crate::{error, message};
use async_trait::async_trait;
use common::primitives;
use std::{fmt::Debug, hash::Hash, sync::Arc};

pub mod libp2p;
pub mod mock;
pub mod types;

/// `NetworkingService` provides the low-level network interface
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
    type Address: Send + Sync + Debug + PartialEq + Eq + Hash + Clone + ToString;

    /// Unique ID assigned to a peer on the network
    type PeerId: Send + Copy + PartialEq + Eq + Hash + Debug + Sync + ToString;

	/// Unique ID assigned to each received request
    type RequestId: Send + Debug + Eq + Hash + Sync;

    /// Enum of different peer discovery strategies that the implementation provides
    type DiscoveryStrategy;

    /// Id that identifies a protocol
    type ProtocolId: Clone + Debug + Eq + PartialEq + Send;

    /// Handle for sending/receiving connecitivity-related events
    type ConnectivityHandle: Send;

    /// Handle for sending/receiving pubsub-related events
    type PubSubHandle: Send;

	/// Handle for sending/receiving request-response events
    type SyncingCodecHandle: Send;

    /// Unique ID assigned to each pubsub message
    type MessageId: Send + Clone + Debug;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `bind_addr` - socket address for incoming P2P traffic
    /// `strategies` - list of strategies that are used for peer discovery
    /// `topics` - list of pubsub topics that the implementation should subscribe to
    /// `timeout` - timeout for outbound connections
    async fn start(
        bind_addr: Self::Address,
        strategies: &[Self::DiscoveryStrategy],
        topics: &[types::PubSubTopic],
        chain_config: Arc<common::chain::ChainConfig>,
        timeout: std::time::Duration,
    ) -> crate::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingCodecHandle,
    )>;
}

/// ConnectivityService provides an interface through which objects can send
/// and receive connectivity-related events to/from the network service provider
#[async_trait]
pub trait ConnectivityService<T>
where
    T: NetworkingService,
{
    /// Connect to a remote node
    ///
    /// If the connection succeeds, the socket object is returned
    /// which can be used to exchange messages with the remote peer
    ///
    /// # Arguments
    /// `addr` - socket address of the peer
    async fn connect(&mut self, address: T::Address) -> crate::Result<types::PeerInfo<T>>;

    /// Disconnect active connection
    ///
    /// # Arguments
    /// `peer_id` - Peer ID of the remote peer
    async fn disconnect(&mut self, peer_id: T::PeerId) -> crate::Result<()>;

    /// Return the socket address of the network service provider
    fn local_addr(&self) -> &T::Address;

    /// Return peer id of the local node
    fn peer_id(&self) -> &T::PeerId;

    /// Poll events from the network service provider
    ///
    /// There are three types of events that can be received:
    /// - incoming peer connections
    /// - new discovered peers
    /// - peer expiration events
    async fn poll_next(&mut self) -> crate::Result<types::ConnectivityEvent<T>>;
}

/// PubSubService provides an interface through which objects can send
/// and receive pubsub-related events to/from the network service provider
#[async_trait]
pub trait PubSubService<T>
where
    T: NetworkingService,
{
    /// Publish data in a given pubsub topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `data` - generic data to send
    async fn publish(&mut self, message: message::Message) -> crate::Result<()>;

    /// Report message validation result back to the backend
    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        msg_id: T::MessageId,
        result: types::ValidationResult,
    ) -> crate::Result<()>;

    /// Poll unvalidated gossipsub messages
    async fn poll_next(&mut self) -> crate::Result<types::PubSubEvent<T>>;
}

#[async_trait]
pub trait SyncingCodecService<T>
where
    T: NetworkingService,
{
    /// Send block/header request to remote
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the peer the request is sent to
    /// `message` - request to be sent
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        message: message::Message,
    ) -> crate::Result<T::RequestId>;

    /// Send block/header response to remote
    ///
    /// # Arguments
    /// `request_id` - ID of the request this is a response to
    /// `message` - response to be sent
    async fn send_response(
        &mut self,
        request_id: T::RequestId,
        message: message::Message,
    ) -> crate::Result<()>;

	/// Poll syncing-related event from the networking service
    async fn poll_next(&mut self) -> crate::Result<types::SyncingEvent<T>>;
}

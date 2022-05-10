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
use common::{chain, primitives};
use std::{fmt::Debug, hash::Hash, sync::Arc};

pub mod libp2p;
pub mod mock;

#[derive(Debug, PartialEq, Eq)]
pub struct AddrInfo<T>
where
    T: NetworkService,
{
    /// Unique ID of the peer
    pub id: T::PeerId,

    /// List of discovered IPv4 addresses
    pub ip4: Vec<Arc<T::Address>>,

    /// List of discovered IPv6 addresses
    pub ip6: Vec<Arc<T::Address>>,
}

#[derive(Debug)]
pub struct PeerInfo<T>
where
    T: NetworkService,
{
    /// Unique ID of the peer
    pub peer_id: T::PeerId,

    /// Peer network
    pub net: chain::config::ChainType,

    /// Peer software version
    pub version: primitives::version::SemVer,

    /// User agent of the peer
    pub agent: Option<String>,

    /// List of supported protocols
    pub protocols: Vec<T::ProtocolId>,
}

// TODO: rename to `SwarmEvent`!
#[derive(Debug)]
pub enum ConnectivityEvent<T>
where
    T: NetworkService,
{
    /// Outbound connection accepted
    ConnectionAccepted {
        /// Peer information
        peer_info: PeerInfo<T>,
    },

    /// Inbound connection received
    IncomingConnection {
        /// Peer address
        addr: T::Address,

        /// Peer information
        peer_info: PeerInfo<T>,
    },

    /// One or more peers discovered
    Discovered {
        /// Address information
        peers: Vec<AddrInfo<T>>,
    },

    /// One one more peers have expired
    Expired {
        /// Address information
        peers: Vec<AddrInfo<T>>,
    },

    /// Peer disconnected
    Disconnected {
        /// Unique ID of the peer
        peer_id: T::PeerId,
    },

    /// Error occurred with peer
    Error {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Error that occurred
        error: error::P2pError,
    },

    /// Peer misbehaved
    Misbehaved {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        // TODO: fix
        behaviour: u32,
    },
}

// TODO: separate events for blocks and transactions?
#[derive(Debug)]
pub enum PubSubEvent<T>
where
    T: NetworkService,
{
    /// Message received from a PubSub topic
    MessageReceived {
        peer_id: T::PeerId,
        message_id: T::MessageId,
        message: message::Message,
    },
}

#[derive(Debug)]
pub enum SyncingMessage<T>
where
    T: NetworkService,
{
    Request {
        peer_id: T::PeerId,
        request_id: T::RequestId,
        request: message::Message,
    },
    Response {
        peer_id: T::PeerId,
        request_id: T::RequestId,
        response: message::Message,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PubSubTopic {
    Transactions,
    Blocks,
}

#[derive(Debug)]
pub enum ValidationResult {
    /// Message was valid and can be forwarded to other peers
    Accept,

    /// Message was invalid and mustn't be forwarded to other peers
    Reject,

    /// Message is not invalid but it shouldn't be forwarded to other peers
    Ignore,
}

/// `NetworkService` provides the low-level network interface
/// that each network service provider must implement
#[async_trait]
pub trait NetworkService {
    /// Generic socket address that the underlying implementation uses
    ///
    /// # Examples
    /// For an implementation built on `TcpListener`, the address format is:
    ///     `0.0.0.0:8888`
    ///
    /// For an implementation built on libp2p, the address format is:
    ///     `/ip4/0.0.0.0/tcp/8888/p2p/<peer ID>`
    type Address: Send + Sync + Debug + PartialEq + Eq + Hash + Clone;

    /// Unique ID assigned to a peer on the network
    type PeerId: Send + Copy + PartialEq + Eq + Hash + Debug;

    // TODO:
    type RequestId: Send + Debug;

    /// Enum of different peer discovery strategies that the implementation provides
    type Strategy;

    /// Id that identifies a protocol
    type ProtocolId: Debug + Send + Clone + PartialEq;

    /// Handle for sending/receiving connecitivity-related events
    type ConnectivityHandle: Send;

    /// Handle for sending/receiving floodsub-related events
    type PubSubHandle: Send;

    // TODO:
    type SyncingHandle: Send;

    /// Unique ID assigned to each pubsub message
    type MessageId: Send + Clone;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `addr` - socket address for incoming P2P traffic
    /// `strategies` - list of strategies that are used for peer discovery
    /// `topics` - list of floodsub topics that the implementation should subscribe to
    /// `timeout` - timeout for outbound connections
    async fn start(
        addr: Self::Address,
        strategies: &[Self::Strategy],
        topics: &[PubSubTopic],
        config: Arc<common::chain::ChainConfig>,
        timeout: std::time::Duration,
    ) -> error::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingHandle,
    )>;
}

// TODO: rename this to swarmhandle!
/// ConnectivityService provides an interface through which objects can send
/// and receive connectivity-related events to/from the network service provider
#[async_trait]
pub trait ConnectivityService<T>
where
    T: NetworkService,
{
    /// Connect to a remote node
    ///
    /// If the connection succeeds, the socket object is returned
    /// which can be used to exchange messages with the remote peer
    ///
    /// # Arguments
    /// `addr` - socket address of the peer
    async fn connect(&mut self, address: T::Address) -> error::Result<PeerInfo<T>>;

    /// Disconnect active connection
    ///
    /// # Arguments
    /// `peer_id` - Peer ID of the remote peer
    async fn disconnect(&mut self, peer_id: T::PeerId) -> error::Result<()>;

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
    async fn poll_next(&mut self) -> error::Result<ConnectivityEvent<T>>;
}

/// PubSubService provides an interface through which objects can send
/// and receive floodsub-related events to/from the network service provider
#[async_trait]
pub trait PubSubService<T>
where
    T: NetworkService,
{
    /// Publish data in a given floodsub topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `data` - generic data to send
    async fn publish(&mut self, message: message::Message) -> error::Result<()>;

    /// Report message validation result back to the backend
    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        msg_id: T::MessageId,
        result: ValidationResult,
    ) -> error::Result<()>;

    /// Poll unvalidated gossipsub messages
    async fn poll_next(&mut self) -> error::Result<PubSubEvent<T>>;
}

#[async_trait]
pub trait SyncingService<T>
where
    T: NetworkService,
{
    // TODO:
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        message: message::Message,
    ) -> error::Result<T::RequestId>;

    // TODO:
    async fn send_response(
        &mut self,
        request_id: T::RequestId,
        message: message::Message,
    ) -> error::Result<()>;

    // TODO:
    async fn poll_next(&mut self) -> error::Result<SyncingMessage<T>>;
}

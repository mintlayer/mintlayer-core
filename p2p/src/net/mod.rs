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
use serialization::{Decode, Encode};
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

#[derive(Debug)]
pub enum ConnectivityEvent<T>
where
    T: NetworkService,
{
    /// Incoming connection from remote peer
    PeerConnected { peer_info: PeerInfo<T> },

    /// One or more peers discovered
    PeerDiscovered { peers: Vec<AddrInfo<T>> },

    /// One one more peers have expired
    PeerExpired { peers: Vec<AddrInfo<T>> },

    /// Peer disconnected
    PeerDisconnected { peer_id: T::PeerId },
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
        topic: PubSubTopic,
        message_id: T::MessageId,
        // TODO: what should the type be here?
        message: message::Message,
        // TODO: use PubSubMessage
    },
    // TODO: peer subscribed/unsubscribed?
}

#[derive(Debug, Encode, Decode)]
pub enum PubSubMessage {
    Transaction(message::Message),
    Block(message::Message),
}

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
        request: message::Message,
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
    type RequestId: Debug;

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

    /// Return the socket address of the network service provider
    fn local_addr(&self) -> &T::Address;

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
    // TODO: use pubsubmessage
    /// Publish data in a given floodsub topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `data` - generic data to send
    async fn publish<U>(&mut self, topic: PubSubTopic, data: &U) -> error::Result<()>
    // TODO: remove these traits bounds
    where
        U: Sync + Send + Encode;

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

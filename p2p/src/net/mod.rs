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
pub enum ConnectivityEvent<T>
where
    T: NetworkService,
{
    /// Incoming connection from remote peer
    IncomingConnection {
        peer_id: T::PeerId,
        socket: T::Socket,
    },

    /// One or more peers discovered
    PeerDiscovered { peers: Vec<AddrInfo<T>> },

    /// One one more peers have expired
    PeerExpired { peers: Vec<AddrInfo<T>> },
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

    /// Generic socket object that the underlying implementation uses
    type Socket: SocketService + Send;

    /// Enum of different peer discovery strategies that the implementation provides
    type Strategy;

    /// Handle for sending/receiving connecitivity-related events
    type ConnectivityHandle: Send;

    /// Handle for sending/receiving floodsub-related events
    type PubSubHandle: Send;

    // TODO: move to pubsubservice??
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
        timeout: std::time::Duration,
    ) -> error::Result<(Self::ConnectivityHandle, Self::PubSubHandle)>;
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
    async fn connect(&mut self, address: T::Address) -> error::Result<(T::PeerId, T::Socket)>;

    /// Return the socket address of the network service provider
    fn local_addr(&self) -> &T::Address;

    /// Poll events from the network service provider
    ///
    /// There are three types of events that can be received:
    /// - incoming peer connections
    /// - new discovered peers
    /// - peer expiration events
    async fn poll_next(&mut self) -> error::Result<ConnectivityEvent<T>>;

    /// Register peer to the network service provider
    async fn register_peer(&mut self, peer: T::PeerId) -> error::Result<()>;

    /// Unregister peer from the network service provider
    async fn unregister_peer(&mut self, peer: T::PeerId) -> error::Result<()>;
}

/// PubSubService provides an interface through which objects can send
/// and receive floodsub-related events to/from the network service provider
#[async_trait]
pub trait PubSubService<T>
where
    T: NetworkService,
{
    // TODO: redesign this!!
    /// Publish data in a given floodsub topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `data` - generic data to send
    async fn publish<U>(&mut self, topic: PubSubTopic, data: &U) -> error::Result<()>
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

/// `SocketService` provides the low-level socket interface that
/// the `NetworkService::Socket` object must implement in order to do networking
#[async_trait]
pub trait SocketService {
    /// Send data to a remote peer we're connected to
    ///
    /// # Arguments
    /// `data` - generic data to send
    async fn send<T>(&mut self, data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode;

    /// Receive data from a remote peer we're connected to
    async fn recv<T>(&mut self) -> error::Result<T>
    where
        T: Decode;
}

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
use crate::error;
use async_trait::async_trait;
use parity_scale_codec::{Decode, Encode};

pub mod libp2p;
pub mod mock;

#[derive(Debug)]
pub enum Event<T>
where
    T: NetworkService,
{
    /// Incoming connection from remote peer
    IncomingConnection(T::PeerId, T::Socket),

    /// One or more peers discovered
    PeerDiscovered(Vec<T::Address>),

    /// One one more peers have expired
    PeerExpired(Vec<T::Address>),
}

#[derive(Debug)]
pub enum GossipSubTopic {
    Transactions,
    Blocks,
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
    type Address: std::fmt::Debug;

    /// Unique ID assigned to a peer on the network
    type PeerId: Send + Copy + PartialEq + Eq + std::hash::Hash;

    /// Unique ID assigned to a peer on the network
    type PeerId: Send + Copy + PartialEq + Eq + std::hash::Hash;

    /// Generic socket object that the underlying implementation uses
    type Socket: SocketService + Send;

    // Enum of different peer discovery strategies that the implementation provides
    type Strategy;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `addr` - socket address for incoming P2P traffic
    /// `strategies` - list of strategies that are used for peer discovery
    /// `topics` - list of gossipsub topics that the implementation should subscribe to
    async fn new(
        addr: Self::Address,
        strategies: &[Self::Strategy],
        topics: &[GossipSubTopic],
    ) -> error::Result<Self>
    where
        Self: Sized;

    /// Connect to a remote node
    ///
    /// If the connection succeeds, the socket object is returned
    /// which can be used to exchange messages with the remote peer
    ///
    /// # Arguments
    /// `addr` - socket address of the peer
    async fn connect(&mut self, addr: Self::Address)
        -> error::Result<(Self::PeerId, Self::Socket)>;

    /// Poll events from the network service provider
    ///
    /// There are three types of events that can be received:
    /// - incoming peer connections
    /// - incoming messages from gossipsub topics
    /// - new discovered peers
    async fn poll_next<T>(&mut self) -> error::Result<Event<T>>
    where
        T: NetworkService<Socket = Self::Socket, Address = Self::Address, PeerId = Self::PeerId>;

    /// Publish data in a given gossip topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `data` - generic data to send
    async fn publish<T>(&mut self, topic: GossipSubTopic, data: &T)
    where
        T: Sync + Send + Encode;
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

// Copyright (c) 2021 RBB S.r.l
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
    type Address;

    /// Generic socket object that the underlying implementation uses
    type Socket: SocketService;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `addr` - socket address for incoming P2P traffic
    async fn new(addr: Self::Address) -> error::Result<Self>
    where
        Self: Sized;

    /// Connect to a remote node
    ///
    /// If the connection succeeds, the socket object is returned
    /// which can be used to exchange messages with the remote peer
    ///
    /// # Arguments
    /// `addr` - socket address of the peer
    async fn connect(&mut self, addr: Self::Address) -> error::Result<Self::Socket>;

    /// Listen for an incoming connection on the P2P port
    ///
    /// When a peer connects, the underlying protocol implementation
    /// performs any initialization/handshaking it needs and then returns
    /// the initialized `Socket` object which the caller of `accept()` can
    /// use to perform the upper-level handshake and initializations.
    ///
    /// This returns a future that the caller must poll and after a connection
    /// with a peer has been established, the function returns. To start listening
    /// for another incoming connection on the P2P port, `accept()` must be called again.
    async fn accept(&mut self) -> error::Result<Self::Socket>;

    /// Publish data in a given gossip topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `data` - generic data to send
    async fn publish<T>(&mut self, topic: &'static str, data: &T)
    where
        T: Sync + Send + Encode;

    /// Subscribe to a gossip topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `tx` - channel for communication between the caller and the event loop
    async fn subscribe<T>(&mut self, topic: &'static str, tx: tokio::sync::mpsc::Sender<T>)
    where
        T: Sync + Send + Decode;
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

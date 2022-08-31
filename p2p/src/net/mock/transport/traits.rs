// Copyright (c) 2022 RBB S.r.l
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

use std::{
    fmt::{Debug, Display},
    hash::Hash,
};

use async_trait::async_trait;

use crate::net::mock::types::Message;

// TODO: FIXME: Better description.
/// An abstraction layer for creating "sockets" ("connections").
#[async_trait]
pub trait TransportService: Sized {
    type Socket: Send;

    // TODO: FIXME: Remove Hash and Display?
    type Address: Copy + Clone + Debug + Display + Eq + Hash + Send + Sync + ToString;

    /// Creates a new socket and binds it to the given address.
    async fn bind(address: Self::Address) -> crate::Result<Self::Socket>;

    /// Creates a new socket and try to establish a connection to the given `address`.
    async fn connect(address: Self::Address) -> crate::Result<Self::Socket>;
}

/// TODO: FIXME: Better description.
#[async_trait]
pub trait SocketService<T: TransportService + 'static> {
    /// Accepts a new inbound connection.
    async fn accept(&mut self) -> crate::Result<(T::Socket, T::Address)>;

    /// Establishes a new outbound connection.
    async fn connect(&mut self) -> crate::Result<T::Socket>;

    /// Sends the given message to a remote peer.
    // TODO: FIXME: Different error type?
    async fn send(&mut self, msg: Message) -> Result<(), std::io::Error>;

    /// Receives a message from a remote peer.
    // TODO: FIXME: Different error type?
    async fn recv(&mut self) -> Result<Option<Message>, std::io::Error>;

    // TODO: FIXME: Do we really need this?
    /// Returns the local address of the socket.
    fn local_addr(&self) -> crate::Result<T::Address>;
}

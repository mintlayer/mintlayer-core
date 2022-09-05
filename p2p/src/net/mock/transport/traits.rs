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

use crate::{net::mock::types::Message, Result};

/// An abstraction layer for creating and opening connections.
#[async_trait]
pub trait Transport {
    // TODO: FIXME: Remove Hash and Display?
    /// An address type.
    type Address: Copy + Clone + Debug + Display + Eq + Hash + Send + Sync + ToString;

    /// A connection type.
    type Connection;

    /// Creates a new connection with the given address.
    async fn bind(address: Self::Address) -> Result<Self::Connection>;

    /// Open a connection to the given address.
    async fn connect(address: Self::Address) -> Result<Self::Connection>;
}

/// An abstraction layer over some kind of network connection.
#[async_trait]
pub trait Connection<T: Transport>: Send {
    /// TODO: FIXME:
    type Stream;

    /// Accepts a new inbound connection.
    async fn accept(&mut self) -> Result<(Self::Stream, T::Address)>;

    // TODO: FIXME:
    // /// Establishes a new outbound connection.
    // async fn connect(&mut self) -> crate::Result<T::Socket>;

    // // TODO: FIXME: Do we really need this?
    // /// Returns the local address of the socket.
    // fn local_addr(&self) -> crate::Result<T::Address>;
}

/// An abstraction layer over some network stream that can be used to send and receive messages.
#[async_trait]
pub trait MessageStream<T: Transport> {
    /// Sends the given message to a remote peer.
    async fn send(&mut self, msg: Message) -> Result<()>;

    /// Receives a message from a remote peer.
    async fn recv(&mut self) -> Result<Option<Message>>;
}

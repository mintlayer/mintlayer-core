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

use async_trait::async_trait;

use crate::net::mock::types::Message;

// TODO: FIXME: Use proper error type.
type Error = ();

/// The abstraction over a network.
#[async_trait]
pub trait NetworkMock {
    /// TODO: FIXME:
    type Address;

    fn new(peers: usize) -> (Self, Vec<Self::Address>)
    where
        Self: Sized;

    // /// TODO: FIXME:
    // // For channels implementation this method generates a peer id (u64) and returns
    // // a tx part of the channel.
    // // Simply returns an address for the tcp implementation.
    // fn add_peer(&mut self) -> Self::Address;

    /// TODO: FIXME:
    // Spawns tokio task for the channels implementation, does nothing for TCP.
    async fn run(self);
}

/// The abstraction layer over a network address.
#[async_trait]
pub trait AddressMock {
    type Connection: ConnectionMock;

    /// Creates a connection with the given address.
    async fn create(self) -> Result<Self::Connection, Error>;

    /// Connects to the address.
    async fn connect(self) -> Result<Self::Connection, Error>;
}

/// The abstraction layer over a connection.
#[async_trait]
pub trait ConnectionMock {
    /// Sends the given message to a peer.
    async fn send(&mut self, msg: Message) -> Result<(), Error>;

    /// Receives a messaged.
    async fn recv(&mut self) -> Result<Option<Message>, Error>;
}

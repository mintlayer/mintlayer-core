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

use std::{fmt::Debug, hash::Hash, str::FromStr};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    net::{AsBannableAddress, IsBannableAddress},
    Result,
};

/// An abstraction layer for creating and opening connections.
#[async_trait]
pub trait MockTransport: Send + Sync + 'static {
    /// An address type.
    type Address: Clone
        + Debug
        + Eq
        + Hash
        + Send
        + Sync
        + ToString
        + FromStr
        + AsBannableAddress<BannableAddress = Self::BannableAddress>
        + IsBannableAddress;

    /// A bannable address format.
    type BannableAddress: Debug + Eq + Ord + Send;

    /// A listener type.
    type Listener: MockListener<Self::Stream, Self::Address>;

    /// A messages stream.
    type Stream: MockStream;

    /// Creates a new transport.
    fn new() -> Self;

    /// Creates a new listener bound to the specified address.
    async fn bind(&self, address: Self::Address) -> Result<Self::Listener>;

    /// Open a connection to the given address.
    async fn connect(&self, address: Self::Address) -> Result<Self::Stream>;
}

/// An abstraction layer over some kind of network connection.
#[async_trait]
pub trait MockListener<Stream, Address>: Send {
    /// Accepts a new inbound connection.
    async fn accept(&mut self) -> Result<(Stream, Address)>;

    /// Returns the local address of the listener.
    fn local_address(&self) -> Result<Address>;
}

/// An abstraction layer over some network stream that can be used to send and receive messages.
#[async_trait]
pub trait MockStream: Unpin + Send + AsyncRead + AsyncWrite {}

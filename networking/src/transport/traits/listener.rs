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

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::Result;

use super::{ConnectedSocketInfo, PeerStream};

/// An abstraction layer over a potential inbound network connection (acceptor in boost terminology).
#[async_trait]
pub trait TransportListener: Send {
    type Stream: PeerStream + ConnectedSocketInfo;

    /// Accepts a new inbound connection.
    ///
    /// The returned address is the same as the one returned by `Stream::remote_address`.
    async fn accept(&mut self) -> Result<(Self::Stream, SocketAddr)>;

    /// Returns the local address of the listener.
    fn local_addresses(&self) -> Result<Vec<SocketAddr>>;
}

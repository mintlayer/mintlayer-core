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

use futures::future::BoxFuture;

use crate::{
    net::mock::{peer::Role, transport::PeerStream},
    Result,
};

/// Represents a stream that requires a handshake to function (such as encrypted streams)
pub trait StreamAdapter<T>: Clone + Send + Sync + 'static {
    type Stream: PeerStream;

    /// Wraps base async stream into AsyncRead/AsyncWrite stream that may implement encryption.
    fn handshake(&self, base: T, role: Role) -> BoxFuture<'static, Result<Self::Stream>>;
}

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

pub mod noise;

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use super::Side;
use crate::Result;

#[async_trait]
pub trait StreamAdapter: Send {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin;

    /// Wraps base async TcpStream into AsyncRead/AsyncWrite stream that implements encryption.
    async fn handshake(base: TcpStream, side: Side) -> Result<Self::Stream>;
}

#[derive(Debug)]
pub struct IdentityStreamAdapter {}

#[async_trait]
impl StreamAdapter for IdentityStreamAdapter {
    type Stream = TcpStream;

    async fn handshake(base: TcpStream, _side: Side) -> Result<Self::Stream> {
        Ok(base)
    }
}

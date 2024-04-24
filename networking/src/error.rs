// Copyright (c) 2021-2024 RBB S.r.l
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

use crate::transport::MpscChannelTransportError;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum NetworkingError {
    // Note: std::io::Error is neither clonable nor comparable, so we only store its "kind" here.
    #[error("IO error: {0}")]
    IoError(std::io::ErrorKind),
    #[error("Message codec error: {0}")]
    MessageCodecError(#[from] MessageCodecError),
    #[error("Noise protocol handshake error")]
    NoiseHandshakeError(String),
    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("Channel transport error: {0}")]
    ChannelTransportError(#[from] MpscChannelTransportError),
}

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum MessageCodecError {
    #[error("Message size {actual_size} exceeds the maximum size {max_size}")]
    MessageTooLarge { actual_size: usize, max_size: usize },
    #[error("Cannot decode data: {0}")]
    InvalidEncodedData(serialization::Error),
}

impl From<std::io::Error> for NetworkingError {
    fn from(value: std::io::Error) -> Self {
        NetworkingError::IoError(value.kind())
    }
}

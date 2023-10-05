// Copyright (c) 2023 RBB S.r.l
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

use enum_iterator::Sequence;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use serialization::{Decode, Encode};

use crate::error::{P2pError, ProtocolError};

/// Network protocol version
///
/// When two nodes connect, they exchange protocol versions,
/// and the minimum version is selected as the negotiated network protocol version.
/// This type represents the "raw" version number that we receive from the peer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn inner(&self) -> u32 {
        self.0
    }
}

/// The validated network protocol version.
#[derive(Copy, Clone, Debug, FromPrimitive, PartialEq, Eq, PartialOrd, Ord, Sequence)]
pub enum SupportedProtocolVersion {
    V1 = 1,
    V2 = 2,
}

impl From<SupportedProtocolVersion> for ProtocolVersion {
    fn from(value: SupportedProtocolVersion) -> Self {
        ProtocolVersion::new(value as u32)
    }
}

impl TryFrom<ProtocolVersion> for SupportedProtocolVersion {
    type Error = P2pError;

    fn try_from(value: ProtocolVersion) -> Result<Self, Self::Error> {
        SupportedProtocolVersion::from_u32(value.inner()).ok_or(P2pError::ProtocolError(
            ProtocolError::UnsupportedProtocol(value),
        ))
    }
}

/// Given this node's and peer's protocol versions (in any order), choose the best version
/// that is supported by both.
pub fn choose_common_protocol_version(
    version1: ProtocolVersion,
    version2: ProtocolVersion,
) -> crate::Result<SupportedProtocolVersion> {
    let min_version = std::cmp::min(version1, version2);
    min_version.try_into()
}

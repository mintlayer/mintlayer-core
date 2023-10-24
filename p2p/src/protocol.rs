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
use utils::make_config_setting;

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

make_config_setting!(HeaderLimit, usize, 2000);
make_config_setting!(MaxLocatorSize, usize, 101);
make_config_setting!(RequestedBlocksLimit, usize, 500);
make_config_setting!(MaxMessageSize, usize, 10 * 1024 * 1024);
make_config_setting!(MaxPeerTxAnnouncements, usize, 5000);
make_config_setting!(MaxUnconnectedHeaders, usize, 10);

/// Protocol configuration. These values are supposed to be modified in tests only.
///
/// Note that there are basically two kinds of values here:
/// 1) The "hard" limits, which are essential parts of the protocol. Modifying such a value
/// even slightly will break the protocol. E.g. sending a `msg_header_count_limit` number of
/// headers signifies that the node may have more headers; modifying this limit even by 1 may
/// cause the peers not to understand each other properly anymore.
/// 2) "Soft" limits, which are intended to control weird behavior. Most peers operate under these
/// limits anyway, so changing them slightly should not lead to protocol incompatibility.
#[derive(Debug, Default)]
pub struct ProtocolConfig {
    // "Hard" limits:
    /// The maximum number of headers that can be sent in one message.
    pub msg_header_count_limit: HeaderLimit,
    /// The maximum number of blocks that can be requested from a single peer.
    pub max_request_blocks_count: RequestedBlocksLimit,

    // "Soft" limits:
    /// The maximum number of elements in a locator.
    pub msg_max_locator_count: MaxLocatorSize,
    /// The maximum size of a p2p message in bytes.
    pub max_message_size: MaxMessageSize,
    /// The maximum number of announcements (hashes) for which we haven't receive transactions.
    pub max_peer_tx_announcements: MaxPeerTxAnnouncements,
    /// The maximum number of singular unconnected headers that a V1 peer can send before
    /// it will be considered malicious.
    pub max_singular_unconnected_headers: MaxUnconnectedHeaders,
}

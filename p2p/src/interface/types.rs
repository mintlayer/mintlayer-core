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

use serde::Serialize;

use crate::types::peer_id::PeerId;

/// Helper type used to return information about a connected peer from RPC.
///
/// `String` is used for types that implement `Display`, but do not have `serde::Serialize`.
#[derive(Debug, Serialize)]
pub struct ConnectedPeer {
    pub peer_id: PeerId,

    pub address: String,

    pub inbound: bool,

    pub ban_score: u32,

    pub user_agent: String,

    pub version: String,

    /// Time spent waiting for a current ping response, in milliseconds
    pub ping_wait: Option<u64>,

    /// Last time for a ping roundtrip, in milliseconds
    pub ping_last: Option<u64>,

    /// Min time for a ping roundtrip, in milliseconds
    pub ping_min: Option<u64>,
}

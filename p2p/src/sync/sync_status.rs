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

use common::primitives::time::Time;

/// Certain information about the current state of block syncing that other parts of p2p
/// (namely, the peer manager) may be interested in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerBlockSyncStatus {
    pub expecting_blocks_since: Option<Time>,
}

impl PeerBlockSyncStatus {
    pub fn new() -> Self {
        Self {
            expecting_blocks_since: None,
        }
    }
}

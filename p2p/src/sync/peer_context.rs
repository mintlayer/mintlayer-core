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

use std::collections::BTreeSet;

use common::{
    chain::block::{Block, BlockHeader},
    primitives::Id,
};

// TODO: Investigate if we need some kind of "timeouts" (waiting for blocks or headers).
// TODO: Track the block availability for a peer.
// TODO: Track the best known block for a peer and take into account the chain work when syncing.
pub struct PeerContext {
    /// A number of blocks that a peer has requested. This shouldn't be bigger than the
    /// `P2pConfig::requested_blocks_limit` value. The actual block identifiers are stored in
    /// `BlockSyncManager::blocks_queue`.
    pub num_blocks_to_send: usize,

    /// A list of blocks that we requested from this peer.
    pub requested_blocks: BTreeSet<Id<Block>>,

    /// A list of headers received via the `HeaderListResponse` message that we haven't yet
    /// requested the blocks for.
    pub known_headers: Vec<BlockHeader>,
}

impl PeerContext {
    pub fn new() -> Self {
        Self {
            num_blocks_to_send: 0,
            requested_blocks: Default::default(),
            known_headers: Default::default(),
        }
    }
}

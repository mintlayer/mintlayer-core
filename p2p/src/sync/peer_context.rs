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

use std::{collections::BTreeSet, sync::Arc};

use common::{
    chain::block::{Block, BlockHeader},
    primitives::Id,
};

use crate::P2pConfig;

// TODO: FIXME: Private fields.
// TODO: Investigate if we need some kind of "timeouts" (waiting for blocks or headers).
pub struct PeerContext {
    p2p_config: Arc<P2pConfig>,

    /// A number of blocks that a peer has requested. This shouldn't be bigger than the
    /// `P2pConfig::requested_blocks_limit` value. The actual block identifiers are stored in
    /// `BlockSyncManager::blocks_queue`.
    num_blocks_to_send: usize,

    /// A list of blocks that we requested from this peer.
    pub requested_blocks: BTreeSet<Id<Block>>,

    /// A list of headers received via the `HeaderListResponse` message that we haven't yet
    /// requested the blocks for.
    pub known_headers: Vec<BlockHeader>,
}

impl PeerContext {
    pub fn new(p2p_config: Arc<P2pConfig>) -> Self {
        Self {
            p2p_config,
            num_blocks_to_send: 0,
            requested_blocks: Default::default(),
            known_headers: Default::default(),
        }
    }
    pub fn num_block_to_send(&self) -> usize {
        self.num_blocks_to_send
    }

    /// Reduces the "number of block to send" by one.
    pub fn decrement_num_block_to_send(&mut self) {
        debug_assert!(self.num_blocks_to_send > 0);
        self.num_blocks_to_send -= 1;
    }

    pub fn add_num_block_to_send(&mut self, n: usize) {
        self.num_blocks_to_send += n;
        debug_assert!(
            self.num_blocks_to_send <= self.p2p_config.requested_blocks_limit.clone().into()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: FIXME:
}

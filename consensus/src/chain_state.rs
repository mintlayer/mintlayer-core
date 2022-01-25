// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): Anton Sinitsyn

use common::chain::block::Block;
use common::chain::ChainConfig;
use common::primitives::{BlockHeight, Id, Idable, H256};
use std::collections::BTreeMap;
use thiserror::Error;

pub type BlockMap = BTreeMap<Id<Block>, BlockIndex>;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    Unknown,
    Valid,
    Failed,
    NoLongerOnMainChain,
    // To be expanded
}

#[allow(dead_code)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlockError {
    #[error("Unknown error")]
    Unknown,
    // Orphan block
    #[error("Orphan")]
    Orphan,
    #[error("Invalid block height `{0}`")]
    InvalidBlockHeight(BlockHeight),
    #[error("The previous block invalid")]
    PrevBlockInvalid,
    #[error("The storage cause failure `{0}`")]
    StorageFailure(blockchain_storage::Error),
    // To be expanded
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tip {
    /// Height of the tip (max height of the fork)
    pub height_tip: BlockHeight,
    /// The last block pushed to the fork
    pub last_block_hash: H256,
    /// The previous block
    pub prev_block_hash: H256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    pub hash_block: H256,
    pub prev_block_hash: H256,
    pub next_block_hash: Option<H256>,
    pub chain_trust: u64,
    pub status: BlockStatus,
    pub height: BlockHeight,
}

impl BlockIndex {
    pub fn new(block: &Block) -> Self {
        Self {
            hash_block: block.get_id().get(),
            prev_block_hash: block.get_prev_block_id().get(),
            next_block_hash: None,
            chain_trust: 0,
            status: BlockStatus::Unknown,
            height: BlockHeight::new(0),
        }
    }

    pub fn get_id(&self) -> Id<Block> {
        Id::new(&self.hash_block)
    }

    pub fn get_prev_block_id(&self) -> Id<Block> {
        Id::new(&self.prev_block_hash)
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.prev_block_hash == H256::zero()
            && chain_config.genesis_block().get_id().get() == self.hash_block
    }

    pub fn get_ancestor(&self, block_map: &BlockMap) -> Result<BlockIndex, BlockError> {
        Ok(*block_map
            .get(&Id::<Block>::new(&self.prev_block_hash))
            .ok_or(BlockError::Orphan)?)
    }
}

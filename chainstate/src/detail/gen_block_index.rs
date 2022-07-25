// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chainstate_types::block_index::BlockIndex;
use common::chain::block::{consensus_data::BlockRewardTransactable, timestamp::BlockTimestamp};
use common::chain::{ChainConfig, GenBlock};
use common::primitives::{BlockHeight, Id};
use common::Uint256;

/// Generalized block index
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum GenBlockIndex<'a> {
    Block(BlockIndex),
    // TODO: This could contain just Genesis + pre-calculated ID
    Genesis(&'a ChainConfig),
}

impl<'a> GenBlockIndex<'a> {
    pub fn block_id(&self) -> Id<GenBlock> {
        match self {
            GenBlockIndex::Block(b) => (*b.block_id()).into(),
            GenBlockIndex::Genesis(c) => c.genesis_block_id(),
        }
    }

    pub fn block_timestamp(&self) -> BlockTimestamp {
        match self {
            GenBlockIndex::Block(b) => b.block_timestamp(),
            GenBlockIndex::Genesis(c) => c.genesis_block().timestamp(),
        }
    }

    pub fn chain_timestamps_max(&self) -> BlockTimestamp {
        match self {
            GenBlockIndex::Block(b) => b.chain_timestamps_max(),
            GenBlockIndex::Genesis(c) => c.genesis_block().timestamp(),
        }
    }

    pub fn block_height(&self) -> BlockHeight {
        match self {
            GenBlockIndex::Block(b) => b.block_height(),
            GenBlockIndex::Genesis(_c) => BlockHeight::zero(),
        }
    }

    pub fn chain_trust(&self) -> &Uint256 {
        match self {
            GenBlockIndex::Block(b) => b.chain_trust(),
            GenBlockIndex::Genesis(_c) => &Uint256::ZERO,
        }
    }

    pub fn block_reward_transactable(&self) -> BlockRewardTransactable {
        match self {
            GenBlockIndex::Block(b) => b.block_header().block_reward_transactable(),
            GenBlockIndex::Genesis(c) => c.genesis_block().block_reward_transactable(),
        }
    }
}

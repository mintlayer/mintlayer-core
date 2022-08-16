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

use chainstate_types::{BlockIndex, EpochData, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{block::BlockReward, Block, GenBlock},
    primitives::{BlockHeight, Id},
};

/// The interface for obtaining a block index by an identifier.
pub trait BlockIndexHandle {
    /// Returns a block index corresponding to the given block.
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError>;

    /// Returns a generalized block index corresponding to the given block or genesis identifier.
    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError>;

    /// Returns an ancestor of the block.
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError>;

    /// Returns the block reward of the given block
    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError>;

    fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, PropertyQueryError>;
}

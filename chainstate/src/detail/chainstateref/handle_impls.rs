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

use chainstate_storage::{BlockchainStorageRead, SealedStorageTag};
use chainstate_types::{
    BlockIndex, BlockIndexHandle, EpochData, GenBlockIndex, PoSAccountingSealedHandle,
    PropertyQueryError,
};
use common::{
    chain::{block::BlockReward, Block, GenBlock, PoolId},
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::PoSAccountingStorageRead;

use crate::TransactionVerificationStrategy;

use super::ChainstateRef;

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> BlockIndexHandle
    for ChainstateRef<'a, S, V>
{
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.get_block_index(block_id)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.get_gen_block_index(block_id)
    }

    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_ancestor(&GenBlockIndex::Block(block_index.clone()), ancestor_height)
            .map_err(PropertyQueryError::from)
    }

    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        self.get_block_reward(block_index)
    }

    fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, PropertyQueryError> {
        self.db_tx.get_epoch_data(epoch_index).map_err(PropertyQueryError::from)
    }
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> PoSAccountingSealedHandle
    for ChainstateRef<'a, S, V>
{
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, PropertyQueryError> {
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&self.db_tx, pool_id)
            .map_err(PropertyQueryError::from)
    }
}

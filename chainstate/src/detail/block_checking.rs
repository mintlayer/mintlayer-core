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

use super::Chainstate;
use crate::{BlockError, TransactionVerificationStrategy};
use chainstate_storage::BlockchainStorage;
use chainstate_types::PropertyQueryError;
use common::{
    chain::{block::signed_block_header::SignedBlockHeader, Block},
    primitives::id::WithId,
};
use utils::tap_error_log::LogError;

pub struct BlockChecker<'a, S, V> {
    chainstate: &'a Chainstate<S, V>,
}

impl<'a, S: BlockchainStorage, V: TransactionVerificationStrategy> BlockChecker<'a, S, V> {
    pub fn new(chainstate: &'a Chainstate<S, V>) -> BlockChecker<'a, S, V> {
        BlockChecker { chainstate }
    }

    pub fn preliminary_block_check(
        &self,
        block: WithId<Block>,
    ) -> Result<WithId<Block>, BlockError> {
        let chainstate_ref = self.chainstate.make_db_tx_ro().map_err(BlockError::from)?;
        let prev_block_id = block.prev_block_id();
        let parent_height = chainstate_ref
            .get_gen_block_index(&prev_block_id)
            .map_err(|e| BlockError::BlockIndexQueryError(prev_block_id, e))?
            .ok_or(BlockError::BlockIndexQueryError(
                prev_block_id,
                PropertyQueryError::BlockIndexNotFound(prev_block_id),
            ))?
            .block_height();

        chainstate_ref.check_block(&block, parent_height.next_height()).log_err()?;
        Ok(block)
    }

    pub fn preliminary_header_check(&self, header: SignedBlockHeader) -> Result<(), BlockError> {
        let chainstate_ref = self.chainstate.make_db_tx_ro().map_err(BlockError::from)?;
        chainstate_ref.check_block_header(&header).log_err()?;
        Ok(())
    }
}

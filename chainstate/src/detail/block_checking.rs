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
use common::{
    chain::{Block, block::signed_block_header::SignedBlockHeader},
    primitives::id::WithId,
};
use utils::tap_log::TapLog;

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
        chainstate_ref.check_block(&block).log_err()?;
        // (experimental) step 11: remember that this block was fully checked,
        // along with the tip it was validated against, so integrate_block can
        // skip the duplicate check if the tip is unchanged by then.
        {
            let tip = chainstate_ref.get_best_block_id().map_err(BlockError::PropertyQueryError)?;
            let mut memo = self.chainstate.pre_checked_blocks.lock().unwrap();
            if memo.len() > 10_000 {
                memo.clear();
            }
            memo.insert(*WithId::id(&block), tip);
        }
        Ok(block)
    }

    pub fn preliminary_headers_check(
        &self,
        headers: &[SignedBlockHeader],
    ) -> Result<(), BlockError> {
        if let Some((first_header, other_headers)) = headers.split_first() {
            let chainstate_ref = self.chainstate.make_db_tx_ro().map_err(BlockError::from)?;

            chainstate_ref.check_block_header(first_header)?;
            chainstate_ref.enforce_checkpoints_for_header_chain(first_header, other_headers)?;
        }

        Ok(())
    }
}

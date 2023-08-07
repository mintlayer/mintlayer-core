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

use crate::sync::local_state::LocalBlockchainState;
use api_server_common::storage::storage_api::{
    ApiStorage, ApiStorageError, ApiStorageRead, ApiStorageWrite, ApiTransactionRw,
};
use common::{
    chain::{Block, GenBlock},
    primitives::{id::WithId, BlockHeight, Id, Idable},
};

#[derive(Debug, thiserror::Error)]
pub enum BlockchainStateError {
    #[error("Unexpected storage error: {0}")]
    StorageError(#[from] ApiStorageError),
}

pub struct BlockchainState<B> {
    storage: B,
}

impl<B: ApiStorage> BlockchainState<B> {
    pub fn new(storage: B) -> Self {
        Self { storage }
    }
}

impl<B: ApiStorage> LocalBlockchainState for BlockchainState<B> {
    type Error = BlockchainStateError;

    fn best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), Self::Error> {
        let db_tx = self.storage.transaction_ro()?;
        let best_block = db_tx.get_best_block()?;
        Ok(best_block)
    }

    fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> Result<(), Self::Error> {
        let mut db_tx = self.storage.transaction_rw()?;

        // Disconnect blocks from main-chain
        while db_tx.get_best_block()?.0 > common_block_height {
            db_tx.del_main_chain_block_id(db_tx.get_best_block()?.0)?;
        }

        for (index, block) in blocks.into_iter().map(WithId::new).enumerate() {
            let block_height = BlockHeight::new(common_block_height.into_int() + index as u64 + 1);

            db_tx.set_main_chain_block_id(block_height, block.get_id())?;

            for tx in block.transactions() {
                db_tx.set_transaction(tx.transaction().get_id(), tx)?;
            }

            db_tx.set_block(block.get_id(), &block)?;
        }

        db_tx.commit()?;

        Ok(())
    }
}

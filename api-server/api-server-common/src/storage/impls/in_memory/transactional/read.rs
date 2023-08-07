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

use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};

use crate::storage::storage_api::{block_aux_data::BlockAuxData, ApiStorageError, ApiStorageRead};

use super::ApiInMemoryStorageTransactionalRo;

impl<'t> ApiStorageRead for ApiInMemoryStorageTransactionalRo<'t> {
    fn is_initialized(&self) -> Result<bool, ApiStorageError> {
        self.transaction.is_initialized()
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiStorageError> {
        self.transaction.get_block(block_id)
    }

    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, ApiStorageError> {
        self.transaction.get_transaction(transaction_id)
    }

    fn get_storage_version(&self) -> Result<Option<u32>, ApiStorageError> {
        self.transaction.get_storage_version()
    }

    fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiStorageError> {
        self.transaction.get_best_block()
    }

    fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiStorageError> {
        self.transaction.get_block_aux_data(block_id)
    }

    fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiStorageError> {
        self.transaction.get_main_chain_block_id(block_height)
    }
}

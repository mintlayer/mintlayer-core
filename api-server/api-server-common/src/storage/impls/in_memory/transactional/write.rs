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
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};

use crate::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiStorageError, ApiStorageRead, ApiStorageWrite,
};

use super::ApiInMemoryStorageTransactionalRw;

impl<'t> ApiStorageWrite for ApiInMemoryStorageTransactionalRw<'t> {
    fn initialize_storage(&mut self, chain_config: &ChainConfig) -> Result<(), ApiStorageError> {
        self.transaction.initialize_storage(chain_config)
    }

    fn set_block(&mut self, block_id: Id<Block>, block: &Block) -> Result<(), ApiStorageError> {
        self.transaction.set_block(block_id, block)
    }

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiStorageError> {
        self.transaction.set_transaction(transaction_id, transaction)
    }

    fn set_storage_version(&mut self, version: u32) -> Result<(), ApiStorageError> {
        self.transaction.set_storage_version(version)
    }

    fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiStorageError> {
        self.transaction.set_best_block(block_height, block_id)
    }

    fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: BlockAuxData,
    ) -> Result<(), ApiStorageError> {
        self.transaction.set_block_aux_data(block_id, block_aux_data)
    }

    fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiStorageError> {
        self.transaction.set_main_chain_block_id(block_height, block_id)
    }

    fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiStorageError> {
        self.transaction.del_main_chain_block_id(block_height)
    }
}

impl<'t> ApiStorageRead for ApiInMemoryStorageTransactionalRw<'t> {
    fn is_initialized(&self) -> Result<bool, ApiStorageError> {
        self.transaction.is_initialized()
    }

    fn get_storage_version(&self) -> Result<Option<u32>, ApiStorageError> {
        self.transaction.get_storage_version()
    }

    fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiStorageError> {
        self.transaction.get_best_block()
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiStorageError> {
        self.transaction.get_block(block_id)
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

    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, ApiStorageError> {
        self.transaction.get_transaction(transaction_id)
    }
}

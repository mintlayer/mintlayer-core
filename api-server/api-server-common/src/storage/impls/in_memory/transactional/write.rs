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
    primitives::{Amount, BlockHeight, Id},
};

use crate::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiServerStorageError, ApiServerStorageRead,
    ApiServerStorageWrite,
};

use super::ApiServerInMemoryStorageTransactionalRw;

#[async_trait::async_trait]
impl<'t> ApiServerStorageWrite for ApiServerInMemoryStorageTransactionalRw<'t> {
    async fn initialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.initialize_storage(chain_config)
    }

    async fn del_address_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.del_address_balance_above_height(block_height)
    }

    async fn set_address_balance_at_height(
        &mut self,
        address: &str,
        amount: Amount,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.set_address_balance_at_height(address, amount, block_height)
    }

    async fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.set_block(block_id, block)
    }

    async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.set_transaction(transaction_id, owning_block, transaction)
    }

    async fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.set_best_block(block_height, block_id)
    }

    async fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.set_block_aux_data(block_id, block_aux_data)
    }

    async fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.set_main_chain_block_id(block_height, block_id)
    }

    async fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction.del_main_chain_block_id(block_height)
    }
}

#[async_trait::async_trait]
impl<'t> ApiServerStorageRead for ApiServerInMemoryStorageTransactionalRw<'t> {
    async fn is_initialized(&self) -> Result<bool, ApiServerStorageError> {
        self.transaction.is_initialized()
    }

    async fn get_storage_version(&self) -> Result<Option<u32>, ApiServerStorageError> {
        Ok(Some(self.transaction.get_storage_version()?))
    }

    async fn get_address_balance(
        &self,
        address: &str,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.transaction.get_address_balance(address)
    }

    async fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        self.transaction.get_best_block()
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiServerStorageError> {
        self.transaction.get_block(block_id)
    }

    async fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        self.transaction.get_block_aux_data(block_id)
    }

    async fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        self.transaction.get_main_chain_block_id(block_height)
    }

    async fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError> {
        self.transaction.get_transaction(transaction_id)
    }
}

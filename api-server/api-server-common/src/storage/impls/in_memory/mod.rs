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

pub mod transactional;

use std::collections::BTreeMap;

use common::{
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};

use crate::storage::storage_api::{block_aux_data::BlockAuxData, ApiStorageError};

use super::CURRENT_STORAGE_VERSION;

pub struct ApiInMemoryStorage {
    block_table: BTreeMap<Id<Block>, Block>,
    block_aux_data_table: BTreeMap<Id<Block>, BlockAuxData>,
    main_chain_blocks_table: BTreeMap<BlockHeight, Id<Block>>,
    transaction_table: BTreeMap<Id<Transaction>, (Id<Block>, SignedTransaction)>,
    best_block: (BlockHeight, Id<GenBlock>),
    storage_version: Option<u32>,
}

impl ApiInMemoryStorage {
    pub fn new(chain_config: &ChainConfig) -> Self {
        Self {
            block_table: BTreeMap::new(),
            block_aux_data_table: BTreeMap::new(),
            main_chain_blocks_table: BTreeMap::new(),
            transaction_table: BTreeMap::new(),
            best_block: (0.into(), chain_config.genesis_block_id()),
            storage_version: None,
        }
    }

    fn is_initialized(&self) -> Result<bool, ApiStorageError> {
        let storage_version_handle = self.storage_version;
        Ok(storage_version_handle.is_some())
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiStorageError> {
        let block_result = self.block_table.get(&block_id);
        let block = match block_result {
            Some(blk) => blk,
            None => return Ok(None),
        };
        Ok(Some(block.clone()))
    }

    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Id<Block>, SignedTransaction)>, ApiStorageError> {
        let transaction_result = self.transaction_table.get(&transaction_id);
        let tx = match transaction_result {
            Some(tx) => tx,
            None => return Ok(None),
        };
        Ok(Some(tx.clone()))
    }

    fn get_storage_version(&self) -> Result<Option<u32>, ApiStorageError> {
        let version_table_handle = self.storage_version;
        Ok(version_table_handle)
    }

    fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiStorageError> {
        let best_block_table_handle = self.best_block;
        Ok(best_block_table_handle)
    }

    fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiStorageError> {
        let block_aux_data_result = self.block_aux_data_table.get(&block_id);
        let block_aux_data = match block_aux_data_result {
            Some(data) => data,
            None => return Ok(None),
        };
        Ok(Some(block_aux_data.clone()))
    }

    fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiStorageError> {
        let block_id_result = self.main_chain_blocks_table.get(&block_height);
        let block_id = match block_id_result {
            Some(id) => id,
            None => return Ok(None),
        };
        Ok(Some(*block_id))
    }
}

impl ApiInMemoryStorage {
    fn initialize_storage(&mut self, chain_config: &ChainConfig) -> Result<(), ApiStorageError> {
        self.best_block = (0.into(), chain_config.genesis_block_id());
        self.storage_version = Some(CURRENT_STORAGE_VERSION);

        Ok(())
    }

    fn set_block(&mut self, block_id: Id<Block>, block: &Block) -> Result<(), ApiStorageError> {
        self.block_table.insert(block_id, block.clone());
        Ok(())
    }

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Id<Block>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiStorageError> {
        self.transaction_table
            .insert(transaction_id, (owning_block, transaction.clone()));
        Ok(())
    }

    fn set_storage_version(&mut self, version: u32) -> Result<(), ApiStorageError> {
        self.storage_version = Some(version);
        Ok(())
    }

    fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiStorageError> {
        self.best_block = (block_height, block_id);
        Ok(())
    }

    fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: BlockAuxData,
    ) -> Result<(), ApiStorageError> {
        self.block_aux_data_table.insert(block_id, block_aux_data);
        Ok(())
    }

    fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiStorageError> {
        self.main_chain_blocks_table.insert(block_height, block_id);
        Ok(())
    }

    fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiStorageError> {
        self.main_chain_blocks_table.remove(&block_height);
        Ok(())
    }
}

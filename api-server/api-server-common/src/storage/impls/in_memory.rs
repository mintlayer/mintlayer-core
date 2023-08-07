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

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use common::{
    chain::{Block, ChainConfig, GenBlock, Transaction},
    primitives::{BlockHeight, Id},
};
use serialization::{DecodeAll, Encode};

use crate::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiStorageError, ApiStorageRead, ApiStorageWrite,
};

pub const CURRENT_STORAGE_VERSION: u32 = 1;

pub type RowIndex = Vec<u8>;
pub type Data = Vec<u8>;

pub struct ApiInMemoryStorage {
    // Synchronization for all tables together
    mutex: RwLock<()>,
    block_table: Arc<RwLock<BTreeMap<RowIndex, Data>>>,
    block_aux_data_table: Arc<RwLock<BTreeMap<Id<Block>, BlockAuxData>>>,
    main_chain_blocks_table: Arc<RwLock<BTreeMap<BlockHeight, Id<Block>>>>,
    transaction_table: Arc<RwLock<BTreeMap<RowIndex, Data>>>,
    best_block: Arc<RwLock<(BlockHeight, Id<GenBlock>)>>,
    storage_version: Arc<RwLock<Option<u32>>>,
}

impl ApiInMemoryStorage {
    pub fn new(chain_config: &ChainConfig) -> Self {
        Self {
            mutex: RwLock::new(()),
            block_table: Arc::new(RwLock::new(BTreeMap::new())),
            block_aux_data_table: Arc::new(RwLock::new(BTreeMap::new())),
            main_chain_blocks_table: Arc::new(RwLock::new(BTreeMap::new())),
            transaction_table: Arc::new(RwLock::new(BTreeMap::new())),
            best_block: Arc::new(RwLock::new((0.into(), chain_config.genesis_block_id()))),
            storage_version: Arc::new(RwLock::new(None)),
        }
    }
}

impl ApiStorageRead for ApiInMemoryStorage {
    fn is_initialized(&self) -> Result<bool, ApiStorageError> {
        let _lock = self.mutex.read().expect("Poisoned mutex");
        let storage_version_handle = self.storage_version.read().expect("Poisoned table mutex");
        Ok(storage_version_handle.is_some())
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiStorageError> {
        let _lock = self.mutex.read().expect("Poisoned mutex");
        let block_table_handle = self.block_table.read().expect("Poisoned table mutex");
        let block_result = block_table_handle.get(&block_id.encode());
        let block_data = match block_result {
            Some(blk) => blk,
            None => return Ok(None),
        };
        let block = Block::decode_all(&mut &block_data[..])
            .map_err(|e| ApiStorageError::DeserializationError(e.to_string()))?;
        Ok(Some(block))
    }

    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<Transaction>, ApiStorageError> {
        let _lock = self.mutex.read().expect("Poisoned mutex");
        let transaction_table_handle = self.transaction_table.read().expect("Poisoned table mutex");
        let transaction_result = transaction_table_handle.get(&transaction_id.encode());
        let transaction_data = match transaction_result {
            Some(tx) => tx,
            None => return Ok(None),
        };
        let tx = Transaction::decode_all(&mut &transaction_data[..])
            .map_err(|e| ApiStorageError::DeserializationError(e.to_string()))?;
        Ok(Some(tx))
    }

    fn get_storage_version(&self) -> Result<Option<u32>, ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");
        let version_table_handle = self.storage_version.read().expect("Poisoned table mutex");
        Ok(*version_table_handle)
    }

    fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");
        let best_block_table_handle = self.best_block.read().expect("Poisoned table mutex");
        Ok(*best_block_table_handle)
    }

    fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiStorageError> {
        let _lock = self.mutex.read().expect("Poisoned mutex");
        let block_aux_data_table_handle =
            self.block_aux_data_table.read().expect("Poisoned table mutex");
        let block_aux_data_result = block_aux_data_table_handle.get(&block_id);
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
        let _lock = self.mutex.read().expect("Poisoned mutex");
        let main_chain_blocks_table_handle =
            self.main_chain_blocks_table.read().expect("Poisoned table mutex");
        let block_id_result = main_chain_blocks_table_handle.get(&block_height);
        let block_id = match block_id_result {
            Some(id) => id,
            None => return Ok(None),
        };
        Ok(Some(*block_id))
    }
}

impl ApiStorageWrite for ApiInMemoryStorage {
    fn initialize_storage(&mut self, chain_config: &ChainConfig) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");

        let mut best_block_table_handle = self.best_block.write().expect("Poisoned table mutex");
        let mut version_table_handle = self.storage_version.write().expect("Poisoned table mutex");

        *best_block_table_handle = (0.into(), chain_config.genesis_block_id());
        *version_table_handle = Some(CURRENT_STORAGE_VERSION);

        Ok(())
    }

    fn set_block(&mut self, block_id: Id<Block>, block: Block) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");
        let mut block_table_handle = self.block_table.write().expect("Poisoned table mutex");
        block_table_handle.insert(block_id.encode(), block.encode());
        Ok(())
    }

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        transaction: Transaction,
    ) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");
        let mut transaction_table_handle =
            self.transaction_table.write().expect("Poisoned table mutex");
        transaction_table_handle.insert(transaction_id.encode(), transaction.encode());
        Ok(())
    }

    fn set_storage_version(&mut self, version: u32) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");

        let mut version_table_handle = self.storage_version.write().expect("Poisoned table mutex");
        *version_table_handle = Some(version);
        Ok(())
    }

    fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");

        let mut best_block_table_handle = self.best_block.write().expect("Poisoned table mutex");
        *best_block_table_handle = (block_height, block_id);
        Ok(())
    }

    fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: BlockAuxData,
    ) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");

        let mut block_aux_data_table_handle =
            self.block_aux_data_table.write().expect("Poisoned table mutex");
        block_aux_data_table_handle.insert(block_id, block_aux_data);
        Ok(())
    }

    fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");

        let mut main_chain_blocks_table_handle =
            self.main_chain_blocks_table.write().expect("Poisoned table mutex");
        main_chain_blocks_table_handle.insert(block_height, block_id);
        Ok(())
    }

    fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");

        let mut main_chain_blocks_table_handle =
            self.main_chain_blocks_table.write().expect("Poisoned table mutex");
        main_chain_blocks_table_handle.remove(&block_height);
        Ok(())
    }
}

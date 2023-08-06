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
    chain::{Block, Transaction},
    primitives::{BlockHeight, Id},
};
use serialization::{DecodeAll, Encode};

use crate::storage::storage_api::{ApiStorageError, ApiStorageRead, ApiStorageWrite};

pub type RowIndex = Vec<u8>;
pub type Data = Vec<u8>;

pub struct ApiInMemoryStorage {
    // Synchronization for all tables together
    mutex: RwLock<()>,
    block_table: Arc<RwLock<BTreeMap<RowIndex, Data>>>,
    transaction_table: Arc<RwLock<BTreeMap<RowIndex, Data>>>,
    best_block: Arc<RwLock<(BlockHeight, Id<Block>)>>,
    storage_version: Arc<RwLock<Option<u32>>>,
}

impl ApiStorageRead for ApiInMemoryStorage {
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

    fn get_best_block(&self) -> Result<(BlockHeight, Id<Block>), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");
        let best_block_table_handle = self.best_block.read().expect("Poisoned table mutex");
        Ok(*best_block_table_handle)
    }
}

impl ApiStorageWrite for ApiInMemoryStorage {
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
        block_id: Id<Block>,
    ) -> Result<(), ApiStorageError> {
        let _lock = self.mutex.write().expect("Poisoned mutex");

        let mut best_block_table_handle = self.best_block.write().expect("Poisoned table mutex");
        *best_block_table_handle = (block_height, block_id);
        Ok(())
    }
}

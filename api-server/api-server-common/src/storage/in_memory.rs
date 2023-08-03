use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use common::{
    chain::{Block, Transaction},
    primitives::Id,
};
use serialization::{DecodeAll, Encode};

use super::storage_api::{ApiStorageError, ApiStorageRead, ApiStorageWrite};

pub type RowIndex = Vec<u8>;
pub type Data = Vec<u8>;

pub struct ApiInMemoryStorage {
    // Synchronization for all tables together
    mutex: RwLock<()>,
    block_table: Arc<RwLock<BTreeMap<RowIndex, Data>>>,
    transaction_table: Arc<RwLock<BTreeMap<RowIndex, Data>>>,
}

impl ApiStorageRead for ApiInMemoryStorage {
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiStorageError> {
        let _handle = self.mutex.read().expect("Poisoned mutex");
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
        let _handle = self.mutex.read().expect("Poisoned mutex");
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
}

impl ApiStorageWrite for ApiInMemoryStorage {
    fn set_block(&self, block_id: Id<Block>, block: Block) -> Result<(), ApiStorageError> {
        let _handle = self.mutex.write().expect("Poisoned mutex");
        let mut block_table_handle = self.block_table.write().expect("Poisoned table mutex");
        block_table_handle.insert(block_id.encode(), block.encode());
        Ok(())
    }

    fn set_transaction(
        &self,
        transaction_id: Id<Transaction>,
        transaction: Transaction,
    ) -> Result<(), ApiStorageError> {
        let _handle = self.mutex.write().expect("Poisoned mutex");
        let mut transaction_table_handle =
            self.transaction_table.write().expect("Poisoned table mutex");
        transaction_table_handle.insert(transaction_id.encode(), transaction.encode());
        Ok(())
    }
}

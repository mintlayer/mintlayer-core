use common::chain::block::Block;
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::primitives::{BlockHeight, H256};

#[allow(dead_code)]
enum StorageError {
    Unknown,
    DatabaseError(storage::DBError),
}

trait BlockchainStorage {
    fn set_storage_version(version: u32) -> Result<(), StorageError>;
    fn get_storage_version() -> Result<Option<u32>, StorageError>;

    fn set_block(block: &Block) -> Result<(), StorageError>;
    fn get_block(block_id: &H256) -> Result<Option<Block>, StorageError>;
    fn del_block() -> Result<(), StorageError>;

    fn set_block_height_in_mainchain(height: &BlockHeight, block_id: &H256);
    fn get_block_height_in_mainchain(height: &BlockHeight);
    fn del_block_height_in_mainchain(height: &BlockHeight);

    fn set_best_block_id(hash: &H256) -> Result<(), StorageError>;
    fn get_best_block_id() -> Result<Option<H256>, StorageError>;

    fn set_mainchain_tx_index(
        tx_id: &H256,
        tx_index: &TxMainChainIndex,
    ) -> Result<(), StorageError>;
    fn get_mainchain_tx_index(tx_id: &H256) -> Result<Option<TxMainChainIndex>, StorageError>;
    fn del_mainchain_tx_index(tx_id: &H256) -> Result<(), StorageError>;

    fn get_mainchain_tx(tx_index: &TxMainChainPosition) -> Result<Transaction, StorageError>;

    fn transaction_begin() -> Result<(), StorageError>;
    fn transaction_commit() -> Result<(), StorageError>;
    fn transaction_abort() -> Result<(), StorageError>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

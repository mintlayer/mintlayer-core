use common::chain::block::Block;
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::primitives::{BlockHeight, H256};

#[allow(dead_code)]
pub enum BlockchainStorageError {
    Unknown,
    DatabaseError(storage::DBError),
}

pub trait BlockchainStorage {
    fn set_storage_version(version: u32) -> Result<(), BlockchainStorageError>;
    fn get_storage_version() -> Result<Option<u32>, BlockchainStorageError>;

    fn set_block(block: &Block) -> Result<(), BlockchainStorageError>;
    fn get_block(block_id: &H256) -> Result<Option<Block>, BlockchainStorageError>;
    fn del_block() -> Result<(), BlockchainStorageError>;

    fn set_block_height_in_mainchain(height: &BlockHeight, block_id: &H256);
    fn get_block_height_in_mainchain(height: &BlockHeight);
    fn del_block_height_in_mainchain(height: &BlockHeight);

    fn set_best_block_id(hash: &H256) -> Result<(), BlockchainStorageError>;
    fn get_best_block_id() -> Result<Option<H256>, BlockchainStorageError>;

    fn set_mainchain_tx_index(
        tx_id: &H256,
        tx_index: &TxMainChainIndex,
    ) -> Result<(), BlockchainStorageError>;
    fn get_mainchain_tx_index(
        tx_id: &H256,
    ) -> Result<Option<TxMainChainIndex>, BlockchainStorageError>;
    fn del_mainchain_tx_index(tx_id: &H256) -> Result<(), BlockchainStorageError>;

    fn get_mainchain_tx(
        tx_index: &TxMainChainPosition,
    ) -> Result<Transaction, BlockchainStorageError>;

    fn transaction_begin() -> Result<(), BlockchainStorageError>;
    fn transaction_commit() -> Result<(), BlockchainStorageError>;
    fn transaction_abort() -> Result<(), BlockchainStorageError>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

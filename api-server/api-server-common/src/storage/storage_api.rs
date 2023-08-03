use common::{
    chain::{Block, Transaction},
    primitives::Id,
};

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ApiStorageError {
    #[error("Low level storage error: {0}")]
    StorageError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

pub trait ApiStorageRead {
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiStorageError>;

    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<Transaction>, ApiStorageError>;
}

pub trait ApiStorageWrite: ApiStorageRead {
    fn set_block(&self, block_id: Id<Block>, block: Block) -> Result<(), ApiStorageError>;

    fn set_transaction(
        &self,
        transaction_id: Id<Transaction>,
        transaction: Transaction,
    ) -> Result<(), ApiStorageError>;
}

pub trait ApiTransactionRw: ApiStorageWrite + ApiStorageRead {
    fn commit(self) -> Result<(), ApiStorageError>;
    fn rollback(self) -> Result<(), ApiStorageError>;
}

pub trait ApiTransactionRo: ApiStorageRead {
    fn close(self) -> Result<(), ApiStorageError>;
}

pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: ApiTransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: ApiTransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, ApiStorageError>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Result<Self::TransactionRw, ApiStorageError>;
}

pub trait ApiStorage: ApiStorageWrite + for<'tx> Transactional<'tx> + Send {}

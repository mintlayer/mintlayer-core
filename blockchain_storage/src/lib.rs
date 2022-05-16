//! Application-level interface for the persistent blockchain storage.

use common::chain::block::block_index::BlockIndex;
use common::chain::block::{Block, BlockHeader};
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::chain::OutPoint;
use common::chain::OutPointSourceId;
use common::primitives::{BlockHeight, Id};
use storage::traits;
use utxo::{BlockUndo, Utxo};

#[cfg(any(test, feature = "mock"))]
pub mod mock;
mod store;
mod utxo_db;

pub use storage::transaction::{TransactionRo, TransactionRw};
pub use store::Store;

/// Blockchain storage error
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum Error {
    #[error("Storage error: {0}")]
    Storage(storage::error::Recoverable),
}

impl From<storage::Error> for Error {
    fn from(e: storage::Error) -> Self {
        Error::Storage(e.recoverable())
    }
}

/// Possibly failing result of blockchain storage query
pub type Result<T> = core::result::Result<T, Error>;

/// Queries on persistent blockchain data
pub trait BlockchainStorageRead {
    /// Get storage version
    fn get_storage_version(&self) -> crate::Result<u32>;

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<Block>>>;

    fn get_block_index(&self, block_index: &Id<Block>) -> crate::Result<Option<BlockIndex>>;

    /// Get block by its hash
    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;

    /// Get outputs state for given transaction in the mainchain
    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> crate::Result<Option<TxMainChainIndex>>;

    /// Get transaction by block ID and position
    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> crate::Result<Option<Transaction>>;

    /// Get mainchain block by its height
    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<Block>>>;

    /// Get mainchain block header by height
    fn get_block_header_by_id(&self, id: &Id<Block>) -> crate::Result<Option<BlockHeader>>;
}

/// Modifying operations on persistent blockchain data
pub trait BlockchainStorageWrite: BlockchainStorageRead {
    /// Set storage version
    fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;

    /// Set the hash of the best block
    fn set_best_block_id(&mut self, id: &Id<Block>) -> crate::Result<()>;

    /// Set the block index
    fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;

    /// Add a new block into the database
    fn add_block(&mut self, block: &Block) -> crate::Result<()>;

    /// Remove block from the database
    fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;

    /// Set state of the outputs of given transaction
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> crate::Result<()>;

    /// Delete outputs state index associated with given transaction
    fn del_mainchain_tx_index(&mut self, tx_id: &OutPointSourceId) -> crate::Result<()>;

    /// Set the mainchain block at given height to be given block.
    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<Block>,
    ) -> crate::Result<()>;

    /// Remove block id from given mainchain height
    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()>;
}

/// Queries to get the Utxo
// this is not exposed outside the crate, because we only want this to be accessible
// using the UtxoDB.
pub(crate) trait UtxoRead {
    fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
    fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<Block>>>;
}

/// Queries to update the Utxo
// this is not exposed outside the crate, because we only want this to be accessible
// using the UtxoDB.
pub(crate) trait UtxoWrite: UtxoRead {
    fn add_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
    fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;
    fn set_best_block_for_utxos(&mut self, block_id: &Id<Block>) -> crate::Result<()>;
}

pub(crate) trait UndoRead {
    fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<BlockUndo>>;
}
pub(crate) trait UndoWrite: UndoRead {
    fn add_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> crate::Result<()>;
    fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;
}

/// Support for transactions over blockchain storage
pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: traits::TransactionRo<Error = crate::Error> + BlockchainStorageRead + 't;

    /// Associated read-write transaction type.
    type TransactionRw: traits::TransactionRw<Error = crate::Error> + BlockchainStorageWrite + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Self::TransactionRo;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Self::TransactionRw;
}

pub trait BlockchainStorage: BlockchainStorageWrite + for<'tx> Transactional<'tx> {}

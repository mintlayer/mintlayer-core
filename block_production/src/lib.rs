#![allow(dead_code, unused_variables)]

use blockchain_storage::{BlockchainStorage, Store};
use common::chain::block::{Block, BlockCreationError};
use common::chain::transaction::Transaction;
use common::chain::ChainConfig;
use common::primitives::consensus_data::ConsensusData;
use common::primitives::Id;
use consensus::PoWError;

//TODO: define definite errors specific to BlockProduction
pub enum BlockProductionError {
    InvalidConsensusParams(String),
    BlockCreationError(BlockCreationError),
    StorageError(blockchain_storage::Error),
    // Pow specific errors
    PoWError(PoWError),
    BlockIdNotFound(Id<Block>),
    NoBlockFound,
}

impl From<PoWError> for BlockProductionError {
    fn from(e: PoWError) -> Self {
        BlockProductionError::PoWError(e)
    }
}

impl From<BlockCreationError> for BlockProductionError {
    fn from(e: BlockCreationError) -> Self {
        BlockProductionError::BlockCreationError(e)
    }
}

impl From<blockchain_storage::Error> for BlockProductionError {
    fn from(e: blockchain_storage::Error) -> Self {
        BlockProductionError::StorageError(e)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub struct BlockProducer;

impl BlockProducer {
    fn verify_block(block: &Block) -> Result<(), BlockProductionError> {
        todo!()
    }

    fn create_block(
        time: u32,
        transactions: Vec<Transaction>,
        store: &mut Store,
        cfg: ChainConfig,
    ) -> Result<Block, BlockProductionError> {
        // TODO: retrieve the netupgrade from cfg, and determine whether it's for pow, pos, etc.

        // get the height based on the best_bloc defined.
        todo!()
    }
}

pub fn create_empty_block(
    prev_block: &Block,
    time: u32,
    transactions: Vec<Transaction>,
) -> Result<Block, BlockCreationError> {
    let hash_prev_block = Id::new(&prev_block.get_merkle_root());
    Block::new(transactions, hash_prev_block, time, ConsensusData::None)
}

fn get_block(store: &mut Store, block_id: Id<Block>) -> Result<Block, BlockProductionError> {
    match store.get_block(block_id.clone()) {
        Ok(Some(block)) => Ok(block),
        Ok(None) => Err(BlockProductionError::BlockIdNotFound(block_id)),
        Err(e) => Err(e.into()),
    }
}

fn get_best_block(store: &mut Store) -> Result<Block, BlockProductionError> {
    match store.get_best_block_id() {
        Ok(Some(block_id)) => get_block(store, block_id),
        Ok(None) => Err(BlockProductionError::NoBlockFound),
        Err(e) => Err(e.into()),
    }
}

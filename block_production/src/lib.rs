#![allow(dead_code, unused_variables)]

mod pow;

pub use crate::pow::POWError;
use common::chain::block::{Block, BlockCreationError};
use common::chain::transaction::Transaction;
use common::chain::ChainConfig;
use common::primitives::{BlockHeight, Id};

//TODO: define definite errors specific to BlockProduction
pub enum BlockProductionError {
    Error1,
    Error2,
    InvalidConsensusParams(String),
    BlockCreationError(BlockCreationError),
    // Pow specific errors
    POWError(crate::pow::POWError),
}

impl From<POWError> for BlockProductionError {
    fn from(e: POWError) -> Self {
        BlockProductionError::POWError(e)
    }
}

impl From<BlockCreationError> for BlockProductionError {
    fn from(e: BlockCreationError) -> Self {
        BlockProductionError::BlockCreationError(e)
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
        cfg: ChainConfig,
        height: BlockHeight,
    ) -> Result<Block, BlockProductionError> {
        // TODO: retrieve the netupgrade from cfg, and determine whether it's for pow, pos, etc.

        todo!()
    }
}

pub fn create_empty_block(
    prev_block: &Block,
    time: u32,
    transactions: Vec<Transaction>,
) -> Result<Block, BlockCreationError> {
    let hash_prev_block = Id::new(&prev_block.get_merkle_root());
    Block::new(transactions, hash_prev_block, time, vec![])
}

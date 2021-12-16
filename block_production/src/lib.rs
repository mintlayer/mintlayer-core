mod pow;

use crate::pow::POWError;
use common::chain::block::{Block, BlockCreationError, ConsensusData};
use common::chain::transaction::Transaction;
use common::primitives::{Uint256, H256};

//TODO: remove until an actual trait is created
pub trait Chain {
    fn get_block_hash(block_number: u32) -> H256;
    fn get_block_number(block_hash: &H256) -> u32;
    fn get_latest_block() -> Block;
    fn get_block_id(block: &Block) -> H256;

    fn add_block(block: Block);
}

//TODO: define definite errors specific to BlockProduction
pub enum BlockProductionError {
    Error1,
    Error2,
    InvalidConsensusParams(String),
    BlockCreationError(BlockCreationError),
    // Pow specific errors
    POWError(crate::pow::POWError),
}

impl From<BlockCreationError> for BlockProductionError {
    fn from(e: BlockCreationError) -> Self {
        BlockProductionError::BlockCreationError(e)
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ConsensusParams {
    /// Proof of Work consensus parameters
    POW {
        max_nonce: u128,
        difficulty: Uint256,
    },
    /// Proof of Stake consensus parameters
    POS,
}

pub trait BlockProducer: Chain {
    //TODO: what other params are needed to verify a block?
    fn verify_block(block: &Block) -> Result<(), BlockProductionError>;

    fn create_block(
        time: u32,
        transactions: Vec<Transaction>,
        consensus_params: ConsensusParams,
    ) -> Result<Block, BlockProductionError>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

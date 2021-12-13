mod pow;

use common::chain::block::{Block, ConsensusData};
use common::chain::transaction::Transaction;
use common::primitives::H256;

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
}

pub trait BlockProducer: Chain {
    //TODO: what other params are needed to verify a block?
    fn verify_block(block: &Block) -> Result<(), BlockProductionError>;

    fn create_block(
        time: u32,
        version: i32,
        transactions: Vec<Transaction>,
        consensus_data: ConsensusData,
    ) -> Result<Block, BlockProductionError>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

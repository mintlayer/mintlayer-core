use crate::pow::traits::{DataExt, PowExt};
use crate::pow::Compact;
use crate::{BlockProducer, BlockProductionError, Chain, ConsensusParams};
use common::chain::block::{Block, BlockCreationError, ConsensusData};
use common::chain::transaction::Transaction;
use common::primitives::{Id, Uint256, H256};

pub struct Pow;

impl Chain for Pow {
    fn get_block_hash(block_number: u32) -> H256 {
        todo!()
    }

    fn get_block_number(block_hash: &H256) -> u32 {
        todo!()
    }

    fn get_latest_block() -> Block {
        todo!()
    }

    fn get_block_id(block: &Block) -> H256 {
        todo!()
    }

    fn add_block(block: Block) {
        todo!()
    }
}

impl BlockProducer for Pow {
    fn verify_block(block: &Block) -> Result<(), BlockProductionError> {
        todo!()
    }

    fn create_block(
        time: u32,
        transactions: Vec<Transaction>,
        consensus_params: ConsensusParams,
    ) -> Result<Block, BlockProductionError> {
        match consensus_params {
            ConsensusParams::POW {
                max_nonce,
                difficulty,
            } => {
                let mut block = Pow::create_empty_block(time, transactions)?;

                block.mine(max_nonce, difficulty)?;

                Ok(block)
            }
            other => Err(BlockProductionError::InvalidConsensusParams(format!(
                "Expecting Proof of Work Consensus Parameters, Actual: {:?}",
                other
            ))),
        }
    }
}

impl Pow {
    pub fn check_difficulty(block: &Block, difficulty: &Uint256) -> bool {
        block.calculate_hash() <= *difficulty
    }

    pub fn create_empty_block(
        time: u32,
        transactions: Vec<Transaction>,
    ) -> Result<Block, BlockCreationError> {
        let hash_prev_block = Self::get_latest_block().get_merkle_root();
        let hash_prev_block = Id::new(&hash_prev_block);
        Block::new(transactions, hash_prev_block, time, ConsensusData::empty())
    }
}

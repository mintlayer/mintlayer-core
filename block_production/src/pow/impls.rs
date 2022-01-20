use crate::pow::traits::{DataExt, PowExt};
use crate::{BlockProducer, BlockProductionError, Chain, ConsensusParams};
use common::chain::block::{Block, BlockCreationError, ConsensusData};
use common::chain::Transaction;
use common::primitives::{Compact, Id, Idable, H256};
use common::Uint256;



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


impl DataExt for ConsensusData {
    fn get_bits(&self) -> Compact {
        todo!()
    }

    fn get_nonce(&self) -> u128 {
        todo!()
    }

    fn create(bits: &Compact, nonce: u128) -> Self {
        todo!()
    }

    fn empty() -> Self {
        vec![]
    }
}

impl PowExt for Block {
    fn calculate_hash(&self) -> Uint256 {
        let id = self.get_id();
        id.get().into() //TODO: needs to be tested
    }

    fn mine(&mut self, max_nonce: u128, difficulty: Uint256) -> Result<(), BlockProductionError> {
        let bits = Compact::from(difficulty);

        for nonce in 0..max_nonce {
            self.update_consensus_data(ConsensusData::create(&bits, nonce));

            if Pow::check_difficulty(self, &difficulty) {
                return Ok(());
            }
        }

        let err = format!("max nonce {} has been reached.", max_nonce);
        return Err(BlockProductionError::BlockToMineError(err));
    }
}

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

use crate::pow::traits::{DataExt, PowExt};
use crate::pow::{
    actual_timespan, Compact, Network, DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_SPACING,
    TARGET_TIMESPAN_SECS,
};
use crate::ConsensusParams::POW;
use crate::{BlockProducer, BlockProductionError, Chain, ConsensusParams, POWNetwork};
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

    fn get_block(block_id: &Id<Block>) -> Block {
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
                network,
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

    pub fn check_difficulty_interval(block_number: u32) -> bool {
        block_number % DIFFICULTY_ADJUSTMENT_INTERVAL != 0
    }

    fn last_non_special_min_difficulty(block: &Block, pow_limit: Compact) -> Compact {
        let mut block = block.clone();
        // Return the last non-special-min-difficulty-rules-block
        loop {
            let height = Self::get_block_number(&block.get_merkle_root());
            let block_bits = block.get_consensus_data().get_bits();
            if height == 0 {
                return block_bits;
            }

            if Self::check_difficulty_interval(height) && block_bits == pow_limit {
                let prev_block_id = block.get_prev_block_id();
                block = Self::get_block(&prev_block_id);
            }
        }
    }

    fn allow_mining_min_difficulty_blocks(new_block_time:u32, prev_block_time:u32) -> bool {
        new_block_time > (prev_block_time + (TARGET_SPACING * 2))
    }

    /// retargeting proof of work
    fn next_work_required(
        prev_block: &Block,
        new_block: &Block,
        network: &Network,
    ) -> Option<Compact> {
        let pow_limit = network.limit();
        let prev_block_bits = prev_block.get_consensus_data().get_bits();
        if network.no_retargeting() {
            return Some(prev_block_bits);
        }

        // limit adjustment step
        let actual_timespan_of_last_2016_blocks =
            actual_timespan(new_block.get_block_time(), prev_block.get_block_time());

        // retarget
        prev_block_bits.into_uint256().map(|old_target| {
            let mut new_target = old_target.mul_u32(actual_timespan_of_last_2016_blocks );
            new_target /= Uint256::from_u64(TARGET_TIMESPAN_SECS as u64).expect("converting u32 to uint256 should not be a problem.");

            if new_target > pow_limit {
                pow_limit
            } else {
                new_target
            }
        })
        .and_then(|result| Compact::from_uint256(resuforlt))
    }

    fn next_work_required_for_testnet(
        prev_block: &Block,
        new_block: &Block,
        network: &Network,
    ) -> Option<Compact> {
        let pow_limit = Compact::from_uint256(network.limit());
        if network.allow_min_difficulty_blocks() {
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            return if Self::allow_mining_min_difficulty_blocks(
                new_block.get_block_time(),
                prev_block.get_block_time()
            )
            {
               pow_limit
            } else {
                // Return the lastwork_required_testnet non-special-min-difficulty-rules-block
                pow_limit.map(|pow_limit| {
                    Self::last_non_special_min_difficulty(&prev_block, pow_limit)
                })
            };
        }

        Some(prev_block.get_consensus_data().get_bits())
    }

    pub fn check_for_work_required(new_block: &Block, network: &POWNetwork) -> Option<Compact> {
        let prev_block_id = new_block.get_prev_block_id();
        let prev_block = Self::get_block(&prev_block_id);
        let prev_block_height = Self::get_block_number(&prev_block.get_merkle_root());

        if  Self::check_difficulty_interval(prev_block_height + 1) {
            return Self::next_work_required_for_testnet(&prev_block,new_block,network);
        }

        Self::next_work_required(&prev_block, new_block, network)
    }
}

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

    pub fn is_retarget_needed(block: &Block) -> bool {
        let hash = block.get_merkle_root();
        let block_height = Self::get_block_number(&hash);

        block_height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0
    }

    fn last_non_special_min_difficulty(block: &Block, network_limit: Compact) -> Compact {
        let mut block = block.clone();
        // Return the last non-special-min-difficulty-rules-block
        loop {
            let height = Self::get_block_number(&block.get_merkle_root());
            let block_bits = block.get_consensus_data().get_bits();
            if height == 0 {
                return block_bits;
            }

            if Self::is_retarget_needed(&block) && block_bits == network_limit {
                let prev_block_id = block.get_prev_block_id();
                block = Self::get_block(&prev_block_id);
            }
        }
    }

    fn calculate_next_work_required(
        prev_block: &Block,
        curr_block: &Block,
        network: &Network,
    ) -> Option<Compact> {
        let network_limit = network.limit();
        if network.no_retargeting() {
            return Some(prev_block.get_consensus_data().get_bits());
        }

        // limit adjustment step
        let actual_timespan =
            actual_timespan(curr_block.get_block_time(), prev_block.get_block_time());

        prev_block
            .get_consensus_data()
            .get_bits()
            .into_uint256()
            .map(|bits| {
                let bits = bits.mul_u32(actual_timespan);
                let bits = bits
                    / Uint256::from_u64(TARGET_TIMESPAN_SECS as u64).expect("this should not fail");

                if bits > network_limit {
                    network_limit
                } else {
                    bits
                }
            })
            .and_then(|result| Compact::from_uint256(result))
    }

    pub fn check_for_work_required(new_block: &Block, network: &POWNetwork) -> Option<Compact> {
        let network_limit = Compact::from_uint256(network.limit());

        let prev_block_id = new_block.get_prev_block_id();
        let mut prev_block = Self::get_block(&prev_block_id);

        if Self::get_block_number(&prev_block.get_merkle_root()) == 0 {
            return network_limit;
        }

        if Self::is_retarget_needed(&new_block) {
            if network.allow_min_difficulty_blocks() {
                // Special difficulty rule for testnet:
                // If the new block's timestamp is more than 2* 10 minutes
                // then allow mining of a min-difficulty block.
                return if new_block.get_block_time()
                    > (prev_block.get_block_time() + (TARGET_SPACING * 2))
                {
                    network_limit
                } else {
                    // Return the last non-special-min-difficulty-rules-block
                    network_limit.map(|net_limit| {
                        Self::last_non_special_min_difficulty(&prev_block, net_limit)
                    })
                };
            }

            return Some(prev_block.get_consensus_data().get_bits());
        }

        Self::calculate_next_work_required(&prev_block, new_block, network)
    }
}

#![allow(dead_code)]

use crate::pow::constants::{
    DIFFICULTY_ADJUSTMENT_INTERVAL, LOWER_TARGET_TIMESPAN_SECS, TARGET_SPACING,
    TARGET_TIMESPAN_UINT256, UPPER_TARGET_TIMESPAN_SECS,
};
use crate::pow::traits::{DataExt, PowExt};
use crate::pow::{Compact, ConversionError, Network};
use crate::{Chain, POWError, POWNetwork};
use common::chain::block::{Block, BlockCreationError, ConsensusData};
use common::chain::transaction::Transaction;
use common::primitives::{Id, Uint256};
use std::ops::Div;

pub struct Pow;

// --------------------------  helper functions --------------------------

fn actual_timespan(curr_block_blocktime: u32, prev_block_blocktime: u32) -> u32 {
    let mut actual_timespan = prev_block_blocktime - curr_block_blocktime;

    if actual_timespan < LOWER_TARGET_TIMESPAN_SECS {
        actual_timespan = LOWER_TARGET_TIMESPAN_SECS;
    }

    if actual_timespan > UPPER_TARGET_TIMESPAN_SECS {
        actual_timespan = UPPER_TARGET_TIMESPAN_SECS;
    }

    actual_timespan
}

pub(crate) fn check_difficulty(block: &Block, difficulty: &Uint256) -> bool {
    block.calculate_hash() <= *difficulty
}

fn check_difficulty_interval(block_number: u32) -> bool {
    block_number % DIFFICULTY_ADJUSTMENT_INTERVAL != 0
}

fn allow_mining_min_difficulty_blocks(new_block_time: u32, prev_block_time: u32) -> bool {
    new_block_time > (prev_block_time + (TARGET_SPACING * 2))
}

fn retarget(timespan: u32, block_bits: Compact, pow_limit: Uint256) -> Result<Compact, POWError> {
    match block_bits.into_uint256() {
        None => {
            return Err(ConversionError::CompactToUInt256.into());
        }
        Some(old_target) => {
            let mut new_target = old_target.mul_u32(timespan);
            new_target = new_target.div(TARGET_TIMESPAN_UINT256);
            new_target = if new_target > pow_limit {
                pow_limit
            } else {
                new_target
            };

            Ok(Compact::from_uint256(new_target))
        }
    }
}

pub fn create_empty_block(
    prev_block: &Block,
    time: u32,
    transactions: Vec<Transaction>,
) -> Result<Block, BlockCreationError> {
    let hash_prev_block = Id::new(&prev_block.get_merkle_root());
    Block::new(transactions, hash_prev_block, time, ConsensusData::empty())
}

impl Pow {
    fn last_non_special_min_difficulty(block: &Block, pow_limit: Compact) -> Compact {
        let mut block = block.clone();
        // Return the last non-special-min-difficulty-rules-block
        loop {
            let height = Self::get_block_number(&block.get_merkle_root());
            let block_bits = block.get_consensus_data().get_bits();
            if height == 0 {
                return block_bits;
            }

            if check_difficulty_interval(height) && block_bits == pow_limit {
                let prev_block_id = block.get_prev_block_id();
                block = Self::get_block(&prev_block_id);
            }
        }
    }

    /// retargeting proof of work
    fn next_work_required(
        time: u32,
        prev_block: &Block,
        network: &Network,
    ) -> Result<Compact, POWError> {
        let pow_limit = network.limit();
        let prev_block_bits = prev_block.get_consensus_data().get_bits();

        if network.no_retargeting() {
            return Ok(prev_block_bits);
        }

        // limit adjustment step
        let actual_timespan_of_last_2016_blocks =
            actual_timespan(time, prev_block.get_block_time());

        // retarget
        retarget(
            actual_timespan_of_last_2016_blocks,
            prev_block_bits,
            pow_limit,
        )
    }

    fn next_work_required_for_testnet(time: u32, prev_block: &Block, network: &Network) -> Compact {
        let pow_limit = Compact::from_uint256(network.limit());
        if network.allow_min_difficulty_blocks() {
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            return if allow_mining_min_difficulty_blocks(time, prev_block.get_block_time()) {
                pow_limit
            } else {
                // Return the lastwork_required_testnet non-special-min-difficulty-rules-block
                Self::last_non_special_min_difficulty(&prev_block, pow_limit)
            };
        }

        prev_block.get_consensus_data().get_bits()
    }

    pub fn check_for_work_required(
        time: u32,
        prev_block: &Block,
        network: &POWNetwork,
    ) -> Result<Compact, POWError> {
        let prev_block_height = Self::get_block_number(&prev_block.get_merkle_root());

        if check_difficulty_interval(prev_block_height + 1) {
            return Ok(Self::next_work_required_for_testnet(
                time, prev_block, network,
            ));
        }

        // TODO: get the ancestor: const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        Self::next_work_required(time, prev_block, network)
    }
}

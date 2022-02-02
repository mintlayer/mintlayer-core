use crate::pow::constants::{
    DIFFICULTY_ADJUSTMENT_INTERVAL, LOWER_TARGET_TIMESPAN_SECS, TARGET_SPACING,
    TARGET_TIMESPAN_UINT256, UPPER_TARGET_TIMESPAN_SECS,
};
use crate::pow::Error;
use common::primitives::{BlockHeight, Compact, H256};
use common::Uint256;
use std::ops::Div;

pub fn actual_timespan(curr_block_blocktime: u32, prev_block_blocktime: u32) -> u32 {
    let mut actual_timespan = prev_block_blocktime - curr_block_blocktime;

    if actual_timespan < LOWER_TARGET_TIMESPAN_SECS {
        actual_timespan = LOWER_TARGET_TIMESPAN_SECS;
    }

    if actual_timespan > UPPER_TARGET_TIMESPAN_SECS {
        actual_timespan = UPPER_TARGET_TIMESPAN_SECS;
    }

    actual_timespan
}

pub fn check_difficulty(block_hash: H256, difficulty: &Uint256) -> bool {
    let id: Uint256 = block_hash.into(); //TODO: needs to be tested

    id <= *difficulty
}

pub fn allow_mining_min_difficulty_blocks(new_block_time: u32, prev_block_time: u32) -> bool {
    new_block_time > (prev_block_time + (TARGET_SPACING * 2))
}

pub(crate) fn check_difficulty_interval(block_height: BlockHeight) -> bool {
    block_height.inner() % DIFFICULTY_ADJUSTMENT_INTERVAL as u64 != 0
}

/// Go back by what we want to be 14 days worth of blocks
pub(crate) fn height_by_difficulty_interval(height: BlockHeight) -> BlockHeight {
    let res = height.inner() - (DIFFICULTY_ADJUSTMENT_INTERVAL - 1) as u64;
    BlockHeight::new(res)
}

pub(crate) fn retarget(
    timespan: u32,
    block_bits: Compact,
    pow_limit: Uint256,
) -> Result<Compact, Error> {
    Uint256::try_from(block_bits)
        .map(|old_target| {
            let mut new_target = old_target.mul_u32(timespan);
            new_target = new_target.div(TARGET_TIMESPAN_UINT256);
            new_target = if new_target > pow_limit {
                pow_limit
            } else {
                new_target
            };
            Compact::from(new_target)
        })
        .map_err(|e| {
            Error::ConversionError(format!(
                "conversion of bits {:?} to Uint256 type: {:?}",
                block_bits, e
            ))
        })
}

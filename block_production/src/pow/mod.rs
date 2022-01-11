mod compact;
pub mod impls;
mod network;
mod pow;
mod traits;

use crate::{BlockProductionError, ConsensusParams};
pub use compact::*;
pub use network::Network;
pub use pow::Pow;

pub const TARGET_TIMESPAN_SECS: u32 = 14 * 24 * 60 * 60; // 2 weeks

pub const TARGET_SPACING: u32 = 10 * 60;
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = TARGET_TIMESPAN_SECS / TARGET_SPACING;

/// taken from: https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L56
pub const TIMESPAN_ADJUSTMENT_FACTOR: u32 = 4;

pub const UPPER_TARGET_TIMESPAN_SECS: u32 = TARGET_TIMESPAN_SECS * TIMESPAN_ADJUSTMENT_FACTOR;
pub const LOWER_TARGET_TIMESPAN_SECS: u32 = TARGET_TIMESPAN_SECS / TIMESPAN_ADJUSTMENT_FACTOR;

pub(crate) fn actual_timespan(curr_block_blocktime: u32, prev_block_blocktime: u32) -> u32 {
    let mut actual_timespan = prev_block_blocktime - curr_block_blocktime;

    if actual_timespan < LOWER_TARGET_TIMESPAN_SECS {
        actual_timespan = LOWER_TARGET_TIMESPAN_SECS;
    }

    if actual_timespan > UPPER_TARGET_TIMESPAN_SECS {
        actual_timespan = UPPER_TARGET_TIMESPAN_SECS;
    }

    actual_timespan
}

pub enum POWError {
    FailedUInt256ToCompact,
}

impl Into<BlockProductionError> for POWError {
    fn into(self) -> BlockProductionError {
        BlockProductionError::POWError(self)
    }
}

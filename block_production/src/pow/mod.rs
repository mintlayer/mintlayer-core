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

/// taken from: https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L56
pub const TIMESPAN_ADJUSTMENT_FACTOR: u32 = 4;

pub enum POWError {
    FailedUInt256ToCompact,
}

impl Into<BlockProductionError> for POWError {
    fn into(self) -> BlockProductionError {
        BlockProductionError::POWError(self)
    }
}

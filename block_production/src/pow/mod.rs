mod compact;
pub mod impls;
mod pow;
mod traits;

use crate::{BlockProductionError, ConsensusParams};
pub use compact::*;
pub use pow::Pow;

pub enum POWError {
    FailedUInt256ToCompact,
}

impl Into<BlockProductionError> for POWError {
    fn into(self) -> BlockProductionError {
        BlockProductionError::POWError(self)
    }
}

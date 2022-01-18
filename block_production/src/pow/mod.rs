pub mod impls;
mod traits;

use crate::{BlockProductionError, ConsensusParams};

pub enum POWError {
    FailedUInt256ToCompact,
}

impl Into<BlockProductionError> for POWError {
    fn into(self) -> BlockProductionError {
        BlockProductionError::POWError(self)
    }
}

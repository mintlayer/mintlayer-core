mod compact;
mod constants;
pub mod impls;
mod network;
mod pow;
mod traits;

use crate::BlockProductionError;
pub use compact::*;
pub use network::Network;
pub use pow::Pow;

pub enum POWError {
    FailedUInt256ToCompact,
}

impl Into<BlockProductionError> for POWError {
    fn into(self) -> BlockProductionError {
        BlockProductionError::POWError(self)
    }
}

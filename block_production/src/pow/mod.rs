mod compact;
mod constants;
pub mod impls;
mod network;
mod pow;
mod traits;

pub use compact::*;
pub use network::Network;
pub use pow::Pow;

pub enum ConversionError {
    CompactToUInt256,
}

impl Into<POWError> for ConversionError {
    fn into(self) -> POWError {
        POWError::FailedConversion(self)
    }
}

pub enum POWError {
    FailedConversion(ConversionError),
    BlockToMineError(String),
}

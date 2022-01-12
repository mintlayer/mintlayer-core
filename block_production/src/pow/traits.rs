use crate::pow::Compact;
use crate::BlockProductionError;
use common::primitives::Uint256;

pub trait DataExt {
    /// Returns the bits
    fn get_bits(&self) -> Compact;

    /// Returns the nonce
    fn get_nonce(&self) -> u128;

    /// Create a ConsensusData for Proof of Work
    fn create(bits: &Compact, nonce: u128) -> Self;

    fn empty() -> Self;
}

/// functions specifically for Proof of Work
pub trait PowExt {
    fn calculate_hash(&self) -> Uint256;

    fn mine(&mut self, max_nonce: u128, bits: Compact) -> Result<(), BlockProductionError>;
}

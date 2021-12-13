mod compact;
mod pow;
mod u256;

pub use compact::*;
pub use u256::*;

pub trait ExtractData {
    /// Returns the bits
    fn get_bits(&self) -> Compact;

    /// Returns the nonce
    fn get_nonce(&self) -> u128;

    /// Create a ConsensusData for Proof of Work
    fn create(bits: &Compact, nonce: u128) -> Self;

    /// the Uint256 conversion of bits
    fn get_difficulty(&self) -> Uint256;
}

/// Calculates the hash of the block for Proof of Work
trait Hashable {
    fn hash(&self) -> Uint256;
}

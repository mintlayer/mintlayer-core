mod compact;
mod pow;

pub use compact::*;
pub use pow::Pow;

use util::Uint256;

pub trait ExtractData {
    fn get_bits(&self) -> Compact;
    fn get_nonce(&self) -> u128;

    fn create(bits: &Compact, nonce: u128) -> Self;

    fn get_difficulty(&self) -> Uint256;
}

trait Hashable {
    fn hash(&self) -> Uint256;
}

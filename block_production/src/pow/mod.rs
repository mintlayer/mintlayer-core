mod compact;
mod pow;
mod u256;

pub use compact::*;
pub use u256::*;

pub trait ExtractData {
    fn get_bits(&self) -> Vec<u8>;
    fn get_nonce(&self) -> u128;

    fn create(bits: &[u8], nonce: u128) -> Self;

    fn get_difficulty(&self) -> U256;
}


pub trait Hashable {
    fn hash(&self) -> U256;
}


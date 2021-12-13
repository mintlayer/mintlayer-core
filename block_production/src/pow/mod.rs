mod compact;
mod pow;
mod u256;

use common::chain::block::{Block, BlockHeader, ConsensusData};
use common::primitives::H256;
pub use compact::*;
pub use u256::*;

pub trait ExtractData {
    fn get_bits(&self) -> Vec<u8>;
    fn get_nonce(&self) -> u128;
    fn get_target(&self) -> U256;

    fn create(bits: &[u8], nonce: u128) -> Self;

    fn get_difficulty(&self) -> U256;
}

impl ExtractData for ConsensusData {
    fn get_bits(&self) -> Vec<u8> {
        todo!()
    }

    fn get_nonce(&self) -> u128 {
        todo!()
    }

    fn get_target(&self) -> U256 {
        let bits = self.get_bits();
        convert_to_u256(bits)
    }

    fn get_difficulty(&self) -> U256 {
        let bits = self.get_bits();
        convert_to_u256(bits)
    }

    fn create(bits: &[u8], nonce: u128) -> Self {
        todo!()
    }
}

pub trait Hashable {
    fn hash(&self) -> U256;
}

impl Hashable for Block {
    fn hash(&self) -> U256 {
        todo!()
    }
}

mod pow;

use common::chain::block::{Block, BlockHeader, ConsensusData};
use common::primitives::{Compact,H256};
use common::Uint256;


pub trait ExtractData {
    fn get_bits(&self) -> Vec<u8>;
    fn get_nonce(&self) -> u128;
    fn get_target(&self) -> Uint256;

    fn create(bits: &[u8], nonce: u128) -> Self;

    fn get_difficulty(&self) -> Uint256;
}

impl ExtractData for ConsensusData {
    fn get_bits(&self) -> Vec<u8> {
        todo!()
    }

    fn get_nonce(&self) -> u128 {
        todo!()
    }

    fn get_target(&self) -> Uint256 {
        let bits = self.get_bits();
        convert_to_Uint256(bits)
    }

    fn get_difficulty(&self) -> Uint256 {
        let bits = self.get_bits();
        convert_to_Uint256(bits)
    }

    fn create(bits: &[u8], nonce: u128) -> Self {
        todo!()
    }
}

pub trait Hashable {
    fn hash(&self) -> Uint256;
}

impl Hashable for Block {
    fn hash(&self) -> Uint256 {
        todo!()
    }
}

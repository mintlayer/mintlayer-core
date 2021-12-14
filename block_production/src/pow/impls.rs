use common::chain::block::{Block, ConsensusData};
use common::primitives::Uint256;
use crate::BlockProductionError;
use crate::pow::{Compact, Pow};
use crate::pow::traits::{DataExt, PowExt};

impl DataExt for ConsensusData {
    fn get_bits(&self) -> Compact {
        todo!()
    }

    fn get_nonce(&self) -> u128 {
        todo!()
    }

    fn create(bits: &Compact, nonce: u128) -> Self {
        todo!()
    }

    fn empty() -> Self {
        vec![]
    }
}

impl PowExt for Block {
    fn calculate_hash(&self) -> Uint256 {
        todo!()
    }

    fn mine(&mut self, max_nonce: u128, difficulty: Uint256) -> Result<(), BlockProductionError> {
        let bits = Compact::from(difficulty);

        for nonce in 0..max_nonce {
            self.update_consensus_data(ConsensusData::create(&bits, nonce));

            if Pow::check_difficulty(self, &difficulty) {
                return Ok(());
            }
        }

        Err(BlockProductionError::Error1)
    }
}
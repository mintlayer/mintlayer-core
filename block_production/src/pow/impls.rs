use crate::pow::traits::{DataExt, PowExt};
use crate::pow::{Compact, POWError, Pow};
use crate::BlockProductionError;
use common::chain::block::{Block, ConsensusData};
use common::primitives::{Idable, Uint256};

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
        let id = self.get_id();
        id.get().into() //TODO: needs to be tested
    }

    fn mine(&mut self, max_nonce: u128, difficulty: Uint256) -> Result<(), BlockProductionError> {
        if let Some(bits) = Compact::from_uint256(difficulty) {
            for nonce in 0..max_nonce {
                self.update_consensus_data(ConsensusData::create(&bits, nonce));

                if Pow::check_difficulty(self, &difficulty) {
                    return Ok(());
                }
            }

            let err = format!("max nonce {} has been reached.", max_nonce);
            return Err(BlockProductionError::BlockToMineError(err));
        }

        Err(POWError::FailedUInt256ToCompact.into())
    }
}

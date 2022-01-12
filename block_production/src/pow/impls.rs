use crate::pow::pow::{check_difficulty, create_empty_block};
use crate::pow::traits::{DataExt, PowExt};
use crate::pow::{Compact, ConversionError, POWError, Pow};
use crate::{BlockProducer, BlockProductionError, Chain, ConsensusParams};
use common::chain::block::{Block, ConsensusData};
use common::chain::Transaction;
use common::primitives::{Id, Idable, Uint256, H256};

impl DataExt for ConsensusData {
    fn get_bits(&self) -> Compact {
        todo!()
    }

    fn get_nonce(&self) -> u128 {
        todo!()
    }

    fn create(_bits: &Compact, _nonce: u128) -> Self {
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

    fn mine(&mut self, max_nonce: u128, bits: Compact) -> Result<(), BlockProductionError> {
        if let Some(difficulty) = bits.clone().into_uint256() {
            for nonce in 0..max_nonce {
                self.update_consensus_data(ConsensusData::create(&bits, nonce));

                if check_difficulty(self, &difficulty) {
                    return Ok(());
                }
            }
        } else {
            return Err(POWError::FailedConversion(ConversionError::CompactToUInt256).into());
        }

        let err = format!("max nonce {} has been reached.", max_nonce);
        return Err(POWError::BlockToMineError(err).into());
    }
}

impl Chain for Pow {
    fn get_block_hash(_block_number: u32) -> H256 {
        todo!()
    }

    fn get_block_number(_block_hash: &H256) -> u32 {
        todo!()
    }

    fn get_latest_block() -> Block {
        todo!()
    }

    fn get_block_id(_block: &Block) -> H256 {
        todo!()
    }

    fn get_block(_block_id: &Id<Block>) -> Block {
        todo!()
    }

    fn add_block(_block: Block) {
        todo!()
    }
}

impl BlockProducer for Pow {
    fn verify_block(_block: &Block) -> Result<(), BlockProductionError> {
        todo!()
    }

    fn create_block(
        time: u32,
        transactions: Vec<Transaction>,
        consensus_params: ConsensusParams,
    ) -> Result<Block, BlockProductionError> {
        match consensus_params {
            ConsensusParams::POW { max_nonce, network } => {
                let prev_block = Self::get_latest_block();
                let mut block = create_empty_block(&prev_block, time, transactions)?;
                let bits = Self::check_for_work_required(time, &prev_block, &network)?;

                block.mine(max_nonce, bits)?;

                Ok(block)
            }
            other => Err(BlockProductionError::InvalidConsensusParams(format!(
                "Expecting Proof of Work Consensus Parameters, Actual: {:?}",
                other
            ))),
        }
    }
}

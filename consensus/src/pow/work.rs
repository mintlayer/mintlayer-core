#![allow(dead_code)]

use crate::pow::config::Config;
use crate::pow::helpers::{
    actual_timespan, check_difficulty, retarget, retarget_block_time, testnet,
};
use crate::pow::temp::BlockIndex;
use crate::pow::Error;
use common::chain::block::Block;
use common::primitives::consensus_data::{ConsensusData, PoWData};
use common::primitives::Idable;
use common::primitives::{BlockHeight, Compact};
use common::Uint256;

pub fn check_proof_of_work(hash: Uint256, bits: Compact) -> bool {
    if let Ok(target) = Uint256::try_from(bits) {
        hash > target
    } else {
        false
    }
}

impl Config {
    pub fn check_for_work_required(
        &self,
        prev_block_index: &BlockIndex,
        _height: BlockHeight,
    ) -> Result<Compact, Error> {
        //TODO: check prev_block_index exists

        // TODO: only for testnet
        // if check_difficulty_interval(height) {
        //     if let ChainType::Testnet = chain_type {
        //         return Ok(self.next_work_required_for_testnet(time, prev_block));
        //     }
        // }

        let retarget_block_time = retarget_block_time(prev_block_index);
        self.next_work_required(retarget_block_time, &prev_block_index)
    }

    /// retargeting proof of work
    fn next_work_required(
        &self,
        retarget_block_time: u32,
        prev_block_index: &BlockIndex,
    ) -> Result<Compact, Error> {
        let pow_limit = self.limit;
        let prev_block_bits = prev_block_index.data.bits();

        if self.no_retargeting {
            return Ok(prev_block_bits);
        }

        // limit adjustment step
        let actual_timespan_of_last_2016_blocks =
            actual_timespan(prev_block_index.get_block_time(), retarget_block_time);

        // retarget
        retarget(
            actual_timespan_of_last_2016_blocks,
            prev_block_bits,
            pow_limit,
        )
    }

    fn next_work_required_for_testnet(&self, time: u32, prev_block_index: &BlockIndex) -> Compact {
        let pow_limit = Compact::from(self.limit);

        if self.allow_min_difficulty_blocks {
            // If the new block's timestamp is more than 2 * 10 minutes
            // then allow mining of a min-difficulty block.
            return if testnet::allow_mining_min_difficulty_blocks(
                time,
                prev_block_index.get_block_time(),
            ) {
                pow_limit
            } else {
                // Return the last work_required_testnet non-special-min-difficulty-rules-block
                testnet::last_non_special_min_difficulty(prev_block_index, pow_limit)
            };
        }

        prev_block_index.data.bits()
    }
}

pub fn mine(block: &mut Block, max_nonce: u128, bits: Compact) -> Result<(), Error> {
    match Uint256::try_from(bits) {
        Ok(difficulty) => {
            for nonce in 0..max_nonce {
                let data = PoWData::new(bits, nonce);

                block.update_consensus_data(ConsensusData::PoW(data));

                if check_difficulty(block.get_id().get(), &difficulty) {
                    return Ok(());
                }
            }
        }
        Err(e) => {
            return Err(Error::ConversionError(format!(
                "conversion of bits {:?} to Uint256 type: {:?}",
                bits, e
            )));
        }
    }

    let err = format!("max nonce {} has been reached.", max_nonce);
    Err(Error::BlockToMineError(err))
}

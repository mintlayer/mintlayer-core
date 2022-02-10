#![allow(dead_code)]

use crate::pow::helpers::{
    calculate_new_target, check_difficulty, is_for_retarget, retarget_block_time, special_rules,
};
use crate::pow::temp::BlockIndex;
use crate::pow::{Error, PoW};
use common::chain::block::Block;
use common::primitives::consensus_data::{ConsensusData, PoWData};
use common::primitives::{Compact, Idable};
use common::Uint256;

pub fn check_proof_of_work(hash: Uint256, bits: Compact) -> bool {
    if let Ok(target) = Uint256::try_from(bits) {
        hash > target
    } else {
        false
    }
}

impl PoW {
    /// The difference (in block time) between the current block and 2016th block before the current one.
    /// This difference should be inclusive between (2 weeks/4) and (2 weeks*4).
    /// See Bitcoin's Protocol rules on [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
    pub fn actual_timespan(&self, prev_block_blocktime: u32, retarget_blocktime: u32) -> u64 {
        let actual_timespan = (prev_block_blocktime - retarget_blocktime) as u64;

        // 2 weeks / 4
        let lower_bound = self.min_target_timespan_in_secs();
        // 2 wees * 4
        let upper_bound = self.max_target_timespan_in_secs();

        if actual_timespan < lower_bound {
            lower_bound
        } else if actual_timespan > upper_bound {
            upper_bound
        } else {
            actual_timespan
        }
    }

    pub fn get_work_required(
        &self,
        prev_block_index: &BlockIndex,
        new_block_time: u32,
    ) -> Result<Compact, Error> {
        //TODO: check prev_block_index exists
        let prev_block_bits = prev_block_index.data.bits();

        if self.no_retargeting() {
            return Ok(prev_block_bits);
        }

        let current_height = prev_block_index
            .height
            .checked_add(1)
            .ok_or_else(|| Error::OutofBounds("max block height has been reached.".to_string()))?;
        let adjustment_interval = self.difficulty_adjustment_interval();

        if is_for_retarget(adjustment_interval, current_height) {
            let retarget_block_time = retarget_block_time(adjustment_interval, prev_block_index);
            self.next_work_required(retarget_block_time, prev_block_index)
        }
        // special difficulty rules
        else if self.allow_min_difficulty_blocks() {
            Ok(self.next_work_required_for_min_difficulty(new_block_time, prev_block_index))
        } else {
            Ok(prev_block_bits)
        }
    }

    /// retargeting proof of work
    fn next_work_required(
        &self,
        retarget_block_time: u32,
        prev_block_index: &BlockIndex,
    ) -> Result<Compact, Error> {
        // limit adjustment step
        let actual_timespan_of_last_interval =
            self.actual_timespan(prev_block_index.get_block_time(), retarget_block_time);

        calculate_new_target(
            actual_timespan_of_last_interval,
            self.target_timespan_in_secs(),
            prev_block_index.data.bits(),
            self.difficulty_limit(),
        )
    }

    fn next_work_required_for_min_difficulty(
        &self,
        new_block_time: u32,
        prev_block_index: &BlockIndex,
    ) -> Compact {
        // If the new block's timestamp is more than 2 * 10 minutes
        // then allow mining of a min-difficulty block.
        if special_rules::is_restart_difficulty(
            self.target_spacing_in_secs(),
            new_block_time,
            prev_block_index.get_block_time(),
        ) {
            return Compact::from(self.difficulty_limit());
        }

        // Return the last non-special-min-difficulty-rules-block
        special_rules::last_non_special_min_difficulty(prev_block_index)
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

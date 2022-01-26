#![allow(dead_code)]

use crate::pow::data::Data;
use crate::pow::helpers::{
    actual_timespan, allow_mining_min_difficulty_blocks, check_difficulty,
    height_by_difficulty_interval, retarget,
};
use crate::pow::temp::BlockIndex;
use crate::BlockProductionError;
use crate::POWError;
use common::chain::block::{Block, ConsensusData};
use common::chain::config::ChainType;
use common::chain::PoWConfig;
use common::primitives::Idable;
use common::primitives::{BlockHeight, Compact};
use common::Uint256;

pub struct Pow;

impl Pow {
    fn last_non_special_min_difficulty(block: &BlockIndex, _pow_limit: Compact) -> Compact {
        // TODO: this requires that a height can be derived.
        // let mut block = block.clone();
        // // Return the last non-special-min-difficulty-rules-block
        // loop {
        //     let height = Self::get_block_number(&block.get_merkle_root());
        //     let block_bits = block.get_consensus_data().get_bits();
        //     if height == 0 {
        //         return block_bits;
        //     }
        //
        //     if check_difficulty_interval(height) && block_bits == pow_limit {
        //         let prev_block_id = block.get_prev_block_id();
        //         block = Self::get_block(&prev_block_id);
        //     }
        // }
        todo!()
    }

    /// retargeting proof of work
    fn next_work_required(
        time: u32,
        prev_block_index: &BlockIndex,
        cfg: &PoWConfig,
    ) -> Result<Compact, POWError> {
        let pow_limit = cfg.limit;
        let prev_block_bits = prev_block_index.data.bits;

        if cfg.no_retargeting {
            return Ok(prev_block_bits);
        }

        // limit adjustment step
        let actual_timespan_of_last_2016_blocks =
            actual_timespan(time, prev_block_index.get_block_time());

        // retarget
        retarget(
            actual_timespan_of_last_2016_blocks,
            prev_block_bits,
            pow_limit,
        )
    }

    fn next_work_required_for_testnet(
        time: u32,
        prev_block_index: &BlockIndex,
        cfg: &PoWConfig,
    ) -> Compact {
        let pow_limit = Compact::from(cfg.limit);

        if cfg.allow_min_difficulty_blocks {
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            return if allow_mining_min_difficulty_blocks(time, prev_block_index.get_block_time()) {
                pow_limit
            } else {
                // Return the last work_required_testnet non-special-min-difficulty-rules-block
                Self::last_non_special_min_difficulty(prev_block_index, pow_limit)
            };
        }

        prev_block_index.data.bits
    }

    pub fn check_for_work_required(
        time: u32,
        prev_block_index: &BlockIndex,
        height: BlockHeight,
        chain_type: ChainType,
    ) -> Result<Compact, POWError> {
        let cfg = PoWConfig::from(chain_type);

        // TODO: only for testnet
        // if check_difficulty_interval(height) {
        //     if let ChainType::Testnet = chain_type {
        //         return Ok(Self::next_work_required_for_testnet(time, prev_block, &cfg));
        //     }
        // }

        let old_height = height_by_difficulty_interval(prev_block_index.height);
        let block_index = prev_block_index.get_ancestor(old_height);
        Self::next_work_required(time, &block_index, &cfg)
    }

    pub fn mine(
        block: &mut Block,
        max_nonce: u128,
        bits: Compact,
    ) -> Result<(), BlockProductionError> {
        match Uint256::try_from(bits) {
            Ok(difficulty) => {
                for nonce in 0..max_nonce {
                    let data = Data { bits, nonce };

                    block.update_consensus_data(ConsensusData::from(data));

                    if check_difficulty(block.get_id().get(), &difficulty) {
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                return Err(POWError::ConversionError(format!(
                    "conversion of bits {:?} to Uint256 type: {:?}",
                    bits, e
                ))
                .into());
            }
        }

        let err = format!("max nonce {} has been reached.", max_nonce);
        Err(POWError::BlockToMineError(err).into())
    }
}

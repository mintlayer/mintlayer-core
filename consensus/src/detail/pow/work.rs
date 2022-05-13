// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): C. Yap

#![allow(dead_code)]

use crate::detail::consensus_validator::BlockIndexHandle;
use crate::detail::pow::helpers::{
    calculate_new_target, due_for_retarget, get_starting_block_time, special_rules,
};

use crate::detail::pow::PoW;
use crate::BlockError;
use common::chain::block::consensus_data::PoWData;
use common::chain::block::{Block, ConsensusData};
use common::chain::block::{BlockHeader, BlockIndex};
use common::chain::config::ChainConfig;
use common::chain::PoWStatus;
use common::chain::TxOutput;
use common::primitives::{Compact, Idable, H256};
use common::Uint256;

fn check_proof_of_work(block_hash: H256, block_bits: Compact) -> Result<bool, BlockError> {
    Uint256::try_from(block_bits)
        .map(|target| {
            let hash: Uint256 = block_hash.into();

            hash <= target
        })
        .map_err(|e| {
            BlockError::Conversion(format!(
                "conversion of {:?} to Uint256 type: {:?}",
                block_bits, e
            ))
        })
}

pub(crate) fn check_pow_consensus(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pow_status: &PoWStatus,
    block_index_handle: &dyn BlockIndexHandle,
) -> Result<(), BlockError> {
    let work_required =
        calculate_work_required(chain_config, header, pow_status, block_index_handle)?;
    if check_proof_of_work(header.block_id().get(), work_required)? {
        Ok(())
    } else {
        Err(BlockError::InvalidPoW)
    }
}

fn calculate_work_required(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pow_status: &PoWStatus,
    block_index_handle: &dyn BlockIndexHandle,
) -> Result<Compact, BlockError> {
    match pow_status {
        PoWStatus::Threshold { initial_difficulty } => Ok(*initial_difficulty),
        PoWStatus::Ongoing => {
            let prev_block_id = header
                .get_prev_block_id()
                .clone()
                .expect("If PoWStatus is `Onging` then we cannot be at genesis");
            let prev_block_index = block_index_handle
                .get_block_index(&prev_block_id)?
                .ok_or(BlockError::NotFound)?;
            PoW::new(chain_config).get_work_required(
                &prev_block_index,
                header.block_time(),
                block_index_handle,
            )
        }
    }
}

impl PoW {
    /// The difference (in block time) between the current block and 2016th block before the current one.
    fn actual_timespan(&self, prev_block_blocktime: u32, retarget_blocktime: u32) -> u64 {
        let actual_timespan = (prev_block_blocktime - retarget_blocktime) as u64;

        num::clamp(
            actual_timespan,
            self.min_target_timespan_in_secs(),
            self.max_target_timespan_in_secs(),
        )
    }

    fn get_work_required(
        &self,
        prev_block_index: &BlockIndex,
        new_block_time: u32,
        db_accessor: &dyn BlockIndexHandle,
    ) -> Result<Compact, BlockError> {
        //TODO: check prev_block_index exists
        let prev_block_bits = {
            if let ConsensusData::PoW(pow_data) =
                prev_block_index.get_block_header().consensus_data()
            {
                pow_data.bits()
            } else {
                return Err(BlockError::NoPowData);
            }
        };

        if self.no_retargeting() {
            return Ok(prev_block_bits);
        }

        let current_height = prev_block_index
            .get_block_height()
            .checked_add(1)
            .expect("max block height has been reached.");

        let adjustment_interval = self.difficulty_adjustment_interval();

        // Only change once per difficulty adjustment interval
        if !due_for_retarget(adjustment_interval, current_height) {
            return if self.allow_min_difficulty_blocks() {
                // special difficulty rules
                Ok(self.next_work_required_for_min_difficulty(new_block_time, prev_block_index))
            } else {
                Ok(prev_block_bits)
            };
        }

        let retarget_block_time =
            get_starting_block_time(adjustment_interval, prev_block_index, db_accessor)?;
        self.next_work_required(retarget_block_time, prev_block_index)
    }

    /// retargeting proof of work
    fn next_work_required(
        &self,
        retarget_block_time: u32,
        prev_block_index: &BlockIndex,
    ) -> Result<Compact, BlockError> {
        // limit adjustment step
        let actual_timespan_of_last_interval =
            self.actual_timespan(prev_block_index.get_block_time(), retarget_block_time);

        let prev_block_bits = {
            if let ConsensusData::PoW(pow_data) =
                prev_block_index.get_block_header().consensus_data()
            {
                pow_data.bits()
            } else {
                return Err(BlockError::NoPowData);
            }
        };

        calculate_new_target(
            actual_timespan_of_last_interval,
            self.target_timespan_in_secs(),
            prev_block_bits,
            self.difficulty_limit(),
        )
        .map_err(Into::into)
    }

    fn next_work_required_for_min_difficulty(
        &self,
        new_block_time: u32,
        prev_block_index: &BlockIndex,
    ) -> Compact {
        // If the new block's timestamp is more than 2 * 10 minutes
        // then allow mining of a min-difficulty block.
        if special_rules::block_production_stalled(
            self.target_spacing().as_secs(),
            new_block_time,
            prev_block_index.get_block_time(),
        ) {
            return Compact::from(self.difficulty_limit());
        }

        // Return the last non-special-min-difficulty-rules-block
        special_rules::last_non_special_min_difficulty(prev_block_index)
    }
}

fn mine(
    block: &mut Block,
    max_nonce: u128,
    bits: Compact,
    block_rewards: Vec<TxOutput>,
) -> Result<bool, BlockError> {
    let mut data = PoWData::new(bits, 0, block_rewards);
    for nonce in 0..max_nonce {
        //TODO: optimize this: https://github.com/mintlayer/mintlayer-core/pull/99#discussion_r809713922
        data.update_nonce(nonce);
        block.update_consensus_data(ConsensusData::PoW(data.clone()));

        if check_proof_of_work(block.get_id().get(), bits)? {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use crate::detail::pow::work::check_proof_of_work;
    use common::chain::config::create_mainnet;
    use common::primitives::{Compact, H256};
    use std::str::FromStr;

    //TODO: add `CalculateNextWorkRequired` test cases from Bitcoin

    #[test]
    fn proof_of_work_ok_test() {
        fn test(bits: u32, hash: &str) {
            let hash = H256::from_str(hash).expect("should not fail");
            let bits = Compact(bits);

            let res = check_proof_of_work(hash, bits).expect("should not fail");
            assert!(res);
        }

        // block 722731
        test(
            386_567_092,
            "000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c",
        );
        // block 721311
        test(
            386_568_320,
            "0000000000000000000838523baafc5f5904e472de7ffba2a431b53179a03eb3",
        );
        //block 2
        test(
            486_604_799,
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
        );

        test(
            0,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn proof_of_work_not_ok_test() {
        let cfg = create_mainnet();
        let pow_cfg = cfg.get_proof_of_work_config();
        let pow_limit = pow_cfg.limit();

        // bigger hash than target
        {
            let bits = Compact::from(pow_limit);
            let hash = H256::from(pow_limit.mul_u32(2));

            let res = check_proof_of_work(hash, bits).expect("should not error out");
            assert!(!res);
        }

        // too easy target
        {
            let bits = Compact::from(pow_limit.mul_u32(2));
            let hash =
                H256::from_str("1000000000000000000000000000000000000000000000000000000000000000")
                    .expect("uh oh");

            let res = check_proof_of_work(hash, bits).expect("should not error out");
            assert!(!res);
        }
    }
}

// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(dead_code)]

use chainstate_types::BlockIndex;
use common::{
    chain::{
        block::consensus_data::PoWData,
        block::{timestamp::BlockTimestamp, Block, BlockHeader, ConsensusData},
        config::ChainConfig,
        PoWStatus,
    },
    primitives::{Compact, Idable, H256},
    Uint256,
};

use crate::{
    pow::{
        error::ConsensusPoWError,
        helpers::{calculate_new_target, due_for_retarget, get_starting_block_time, special_rules},
        PoW,
    },
    validator::BlockIndexHandle,
};

pub fn check_proof_of_work(
    block_hash: H256,
    block_bits: Compact,
) -> Result<bool, ConsensusPoWError> {
    Uint256::try_from(block_bits)
        .map(|target| {
            let hash: Uint256 = block_hash.into();

            hash <= target
        })
        .map_err(|_| ConsensusPoWError::DecodingBitsFailed(block_bits))
}

pub fn check_pow_consensus<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pow_status: &PoWStatus,
    block_index_handle: &H,
) -> Result<(), ConsensusPoWError> {
    let work_required =
        calculate_work_required(chain_config, header, pow_status, block_index_handle)?;
    if check_proof_of_work(header.block_id().get(), work_required)? {
        Ok(())
    } else {
        Err(ConsensusPoWError::InvalidPoW(header.get_id()))
    }
}

fn calculate_work_required<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pow_status: &PoWStatus,
    block_index_handle: &H,
) -> Result<Compact, ConsensusPoWError> {
    match pow_status {
        PoWStatus::Threshold { initial_difficulty } => Ok(*initial_difficulty),
        PoWStatus::Ongoing => {
            let prev_block_id = header
                .prev_block_id()
                .classify(chain_config)
                .chain_block_id()
                .expect("If PoWStatus is `Ongoing` then we cannot be at genesis");

            let prev_block_index = match block_index_handle.get_block_index(&prev_block_id) {
                Ok(id) => id,
                Err(err) => {
                    return Err(ConsensusPoWError::PrevBlockLoadError(
                        prev_block_id,
                        header.get_id(),
                        err,
                    ))
                }
            };

            let prev_block_index = prev_block_index.ok_or_else(|| {
                ConsensusPoWError::PrevBlockNotFound(prev_block_id, header.get_id())
            })?;

            PoW::new(chain_config).get_work_required(
                &prev_block_index,
                header.timestamp(),
                block_index_handle,
            )
        }
    }
}

impl PoW {
    /// The difference (in block time) between the current block and 2016th block before the current one.
    fn actual_timespan(&self, prev_block_blocktime: u64, retarget_blocktime: u64) -> u64 {
        // TODO: this needs to be fixed because it could suffer from an underflow
        let actual_timespan = (prev_block_blocktime - retarget_blocktime) as u64;

        num::clamp(
            actual_timespan,
            self.min_target_timespan_in_secs(),
            self.max_target_timespan_in_secs(),
        )
    }

    fn get_work_required<H: BlockIndexHandle>(
        &self,
        prev_block_index: &BlockIndex,
        new_block_time: BlockTimestamp,
        db_accessor: &H,
    ) -> Result<Compact, ConsensusPoWError> {
        let prev_block_consensus_data = prev_block_index.block_header().consensus_data();
        // this function should only be called when consensus status is PoW::Ongoing, i.e. previous
        // block was PoW
        debug_assert!(matches!(prev_block_consensus_data, ConsensusData::PoW(..)));
        let prev_block_bits = {
            if let ConsensusData::PoW(pow_data) = prev_block_consensus_data {
                pow_data.bits()
            } else {
                return Err(ConsensusPoWError::NoPowDataInPreviousBlock);
            }
        };

        if self.no_retargeting() {
            return Ok(prev_block_bits);
        }

        let current_height = prev_block_index
            .block_height()
            .checked_add(1)
            .expect("max block height has been reached.");

        let adjustment_interval = self.difficulty_adjustment_interval();

        // Only change once per difficulty adjustment interval
        if !due_for_retarget(adjustment_interval, current_height) {
            return if self.allow_min_difficulty_blocks() {
                // special difficulty rules
                Ok(self.next_work_required_for_min_difficulty(
                    new_block_time.as_int_seconds(),
                    prev_block_index,
                    prev_block_bits,
                ))
            } else {
                Ok(prev_block_bits)
            };
        }

        let retarget_block_time =
            get_starting_block_time(adjustment_interval, prev_block_index, db_accessor)?;
        self.next_work_required(retarget_block_time, prev_block_index, prev_block_bits)
    }

    /// retargeting proof of work
    fn next_work_required(
        &self,
        retarget_block_time: BlockTimestamp,
        prev_block_index: &BlockIndex,
        prev_block_bits: Compact,
    ) -> Result<Compact, ConsensusPoWError> {
        // limit adjustment step
        let actual_timespan_of_last_interval = self.actual_timespan(
            prev_block_index.block_timestamp().as_int_seconds(),
            retarget_block_time.as_int_seconds(),
        );

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
        new_block_time: u64,
        prev_block_index: &BlockIndex,
        prev_block_bits: Compact,
    ) -> Compact {
        // If the new block's timestamp is more than 2 * 10 minutes
        // then allow mining of a min-difficulty block.
        if special_rules::block_production_stalled(
            self.target_spacing().as_secs(),
            new_block_time,
            prev_block_index.block_timestamp().as_int_seconds(),
        ) {
            Compact::from(self.difficulty_limit())
        } else {
            prev_block_bits
        }
    }
}

pub fn mine(block: &mut Block, max_nonce: u128, bits: Compact) -> Result<bool, ConsensusPoWError> {
    let mut data = PoWData::new(bits, 0);
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
    use crate::pow::work::check_proof_of_work;
    use common::chain::config::create_mainnet;
    use common::primitives::{Compact, H256};
    use rstest::rstest;
    use std::str::FromStr;

    //TODO: add `CalculateNextWorkRequired` test cases from Bitcoin

    #[rstest]
    #[case(0, "0000000000000000000000000000000000000000000000000000000000000000")]
    #[case(
        386_567_092,
        "000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c"
    )] // block 722731
    #[case(
        386_568_320,
        "0000000000000000000838523baafc5f5904e472de7ffba2a431b53179a03eb3"
    )] // block 721311
    #[case(
        486_604_799,
        "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"
    )] // block 2
    fn pow_ok(#[case] bits: u32, #[case] hash: H256) {
        assert!(check_proof_of_work(hash, Compact(bits)).unwrap());
    }

    #[test]
    fn hash_bigger_than_target() {
        let cfg = create_mainnet();
        let pow_limit = cfg.get_proof_of_work_config().limit();

        let bits = Compact::from(pow_limit);
        let hash = H256::from(pow_limit.mul_u32(2));

        assert!(!check_proof_of_work(hash, bits).unwrap());
    }

    #[test]
    fn too_easy_target() {
        let cfg = create_mainnet();
        let pow_limit = cfg.get_proof_of_work_config().limit();

        let bits = Compact::from(pow_limit.mul_u32(2));
        let hash =
            H256::from_str("1000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        assert!(!check_proof_of_work(hash, bits).unwrap());
    }
}

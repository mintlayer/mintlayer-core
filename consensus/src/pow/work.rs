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

use std::sync::Arc;

use chainstate_types::{BlockIndex, BlockIndexHandle, GenBlockIndex};
use common::{
    chain::{
        block::consensus_data::PoWData,
        block::{timestamp::BlockTimestamp, BlockHeader, ConsensusData},
        config::ChainConfig,
        GenBlockId, PoWStatus,
    },
    primitives::{BlockHeight, Compact, Idable, H256},
    Uint256,
};
use utils::atomics::RelaxedAtomicBool;

use crate::{
    get_ancestor_from_block_index_handle,
    pow::{
        error::ConsensusPoWError,
        helpers::{calculate_new_target, due_for_retarget, get_starting_block_time, special_rules},
        PoW,
    },
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
    block_pow_data: &PoWData,
    pow_status: &PoWStatus,
    block_index_handle: &H,
) -> Result<(), ConsensusPoWError> {
    let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
        get_ancestor_from_block_index_handle(block_index_handle, block_index, ancestor_height)
    };

    let work_required = match pow_status {
        PoWStatus::Threshold { initial_difficulty } => *initial_difficulty,
        PoWStatus::Ongoing => match header.prev_block_id().classify(chain_config) {
            GenBlockId::Genesis(_) => PoW::new(chain_config).difficulty_limit().into(),
            GenBlockId::Block(prev_id) => {
                let prev_block_index = block_index_handle
                    .get_block_index(&prev_id)
                    .map_err(|e| ConsensusPoWError::PrevBlockLoadError(prev_id, e))?
                    .ok_or(ConsensusPoWError::PrevBlockNotFound(prev_id))?;

                PoW::new(chain_config).get_work_required(
                    &prev_block_index,
                    header.timestamp(),
                    get_ancestor,
                )?
            }
        },
    };

    // TODO: add test for a block with invalid target
    utils::ensure!(
        work_required == block_pow_data.bits(),
        ConsensusPoWError::InvalidTargetBits(block_pow_data.bits(), work_required)
    );

    if check_proof_of_work(header.block_id().to_hash(), work_required)? {
        Ok(())
    } else {
        Err(ConsensusPoWError::InvalidPoW(header.get_id()))
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningResult {
    Success,
    Failed,
    Stopped,
}

impl MiningResult {
    pub fn is_success(&self) -> bool {
        *self == Self::Success
    }
}

pub fn calculate_work_required<G>(
    chain_config: &ChainConfig,
    prev_gen_block_index: &GenBlockIndex,
    block_timestamp: BlockTimestamp,
    pow_status: &PoWStatus,
    get_ancestor: G,
) -> Result<Compact, ConsensusPoWError>
where
    G: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, crate::ChainstateError>,
{
    match pow_status {
        PoWStatus::Threshold { initial_difficulty } => Ok(*initial_difficulty),
        PoWStatus::Ongoing => match prev_gen_block_index {
            GenBlockIndex::Genesis(_) => Ok(PoW::new(chain_config).difficulty_limit().into()),
            GenBlockIndex::Block(prev_block_index) => PoW::new(chain_config).get_work_required(
                prev_block_index,
                block_timestamp,
                get_ancestor,
            ),
        },
    }
}

impl PoW {
    /// The difference (in block time) between the current block and 2016th block before the current one.
    fn actual_timespan(&self, prev_block_blocktime: u64, retarget_blocktime: u64) -> u64 {
        // TODO: this needs to be fixed because it could suffer from an underflow
        let actual_timespan = prev_block_blocktime - retarget_blocktime;

        num::clamp(
            actual_timespan,
            self.min_target_timespan_in_secs(),
            self.max_target_timespan_in_secs(),
        )
    }

    fn get_work_required<F>(
        &self,
        prev_block_index: &BlockIndex,
        new_block_time: BlockTimestamp,
        get_ancestor: F,
    ) -> Result<Compact, ConsensusPoWError>
    where
        F: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, crate::ChainstateError>,
    {
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
            get_starting_block_time(adjustment_interval, prev_block_index, get_ancestor)?;
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

pub fn mine(
    block_header: &mut BlockHeader,
    max_nonce: u128,
    bits: Compact,
    stop_flag: Arc<RelaxedAtomicBool>,
) -> Result<MiningResult, ConsensusPoWError> {
    let mut data = Box::new(PoWData::new(bits, 0));
    for nonce in 0..max_nonce {
        //TODO: optimize this: https://github.com/mintlayer/mintlayer-core/pull/99#discussion_r809713922
        data.update_nonce(nonce);
        block_header.update_consensus_data(ConsensusData::PoW(data.clone()));

        if check_proof_of_work(block_header.get_id().to_hash(), bits)? {
            return Ok(MiningResult::Success);
        }

        if stop_flag.load() {
            return Ok(MiningResult::Stopped);
        }
    }

    Ok(MiningResult::Failed)
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
        "6c13667de68cb99b4ca3b8aaabe5513e68b90301a59f05000000000000000000"
    )] // block 722731
    #[case(
        386_568_320,
        "b33ea07931b531a42afbff7e2d474e905faafcb2385308000000000000000000"
    )] // block 721311
    #[case(
        486_604_799,
        "bdd99dc9fda39da1b108ce1a5d7030d0a9607bacb68b6b63605f626a00000000"
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
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000010")
                .unwrap();

        assert!(!check_proof_of_work(hash, bits).unwrap());
    }
}

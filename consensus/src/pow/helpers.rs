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

use std::num::NonZeroU64;

use chainstate_types::{BlockIndex, GenBlockIndex};
use common::{
    chain::block::timestamp::BlockTimestamp,
    primitives::{BlockHeight, Compact},
    Uint256,
};

use crate::pow::error::ConsensusPoWError;

/// checks if retargeting is due for the provided block_height
pub fn due_for_retarget(difficulty_adjustment_interval: u64, block_height: BlockHeight) -> bool {
    let height: u64 = block_height.into();
    height % difficulty_adjustment_interval == 0
}

/// The block time of the first block, based on the difficulty adjustment interval,
/// where first block = height of given block - difficulty adjustment interval - 1 (off by one)
pub fn get_starting_block_time<F>(
    difficulty_adjustment_interval: u64,
    block_index: &BlockIndex,
    get_ancestor: F,
) -> Result<BlockTimestamp, ConsensusPoWError>
where
    F: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, crate::ChainstateError>,
{
    let retarget_height = {
        let height: u64 = block_index.block_height().into();
        // Go back by what we want to be 14 days worth of blocks (the last 2015 blocks)
        let old_block_height = height - (difficulty_adjustment_interval - 1);
        BlockHeight::new(old_block_height)
    };

    let retarget_block_index = get_ancestor(block_index, retarget_height)?;

    Ok(retarget_block_index.block_timestamp())
}

/// Returns a calculated new target as Compact datatype.
/// See Bitcoin's Protocol rules of [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
/// # Arguments
/// `actual_timespan_of_last_interval` - the actual timespan or the difference between the current block
/// and the 2016th block before it. This should be in seconds.
/// `target_timespan` - found in the `PoWChainConfig`. This should be in seconds.
/// `old_target` - Coming from the last block, this is the `bits` of the PoWData.
/// `difficulty_limit` - found in the PoWChainConfig, as `limit`
pub fn calculate_new_target(
    actual_timespan_of_last_interval: u64,
    target_timespan: NonZeroU64,
    old_target: Compact,
    difficulty_limit: Uint256,
) -> Result<Compact, ConsensusPoWError> {
    let actual_timespan = Uint256::from_u64(actual_timespan_of_last_interval);

    let target_timespan = Uint256::from_u64(target_timespan.get());

    let old_target = Uint256::try_from(old_target)
        .map_err(|_| ConsensusPoWError::PreviousBitsDecodingFailed(old_target))?;

    // new target is computed by  multiplying the old target by ratio of the actual timespan / target timespan.
    // see Bitcoin's Protocol rules of Difficulty change: https://en.bitcoin.it/wiki/Protocol_rules
    let mut new_target = (old_target * actual_timespan).unwrap_or(Uint256::MAX);
    new_target =
        (new_target / target_timespan).expect("target_timespan cannot be zero as per its type");

    new_target = if new_target > difficulty_limit {
        difficulty_limit
    } else {
        new_target
    };

    Ok(Compact::from(new_target))
}

pub mod special_rules {

    /// Checks if it took > 20 minutes to find a block
    pub fn block_production_stalled(
        target_spacing_in_secs: u64,
        new_block_time: u64,
        prev_block_time: u64,
    ) -> bool {
        new_block_time > (prev_block_time + (target_spacing_in_secs * 2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::primitives::BlockHeight;

    #[test]
    fn due_for_retarget_test() {
        let interval = 2016;
        let test = |h: BlockHeight| due_for_retarget(interval, h);

        assert!(test(BlockHeight::zero()));
        assert!(!test(BlockHeight::one()));
        assert!(test(BlockHeight::new(interval)));
        assert!(!test(BlockHeight::new(interval + 1)));
        assert!(test(BlockHeight::new(interval * 2)));
        assert!(test(BlockHeight::new(interval * 5)));
        assert!(test(BlockHeight::new(interval * 10)));
        assert!(!test(BlockHeight::new((interval * 10) + 1)));
        assert!(!test(BlockHeight::new((interval * 10) - 1)));
    }
}

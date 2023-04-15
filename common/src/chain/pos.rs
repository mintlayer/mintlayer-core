// Copyright (c) 2022 RBB S.r.l
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

use typename::TypeName;

use crate::{
    primitives::{BlockDistance, Id},
    Uint256,
};

#[derive(Eq, PartialEq, TypeName)]
pub enum Pool {}
pub type PoolId = Id<Pool>;

#[derive(Eq, PartialEq, TypeName)]
pub enum Delegation {}
pub type DelegationId = Id<Delegation>;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PoSChainConfig {
    /// The lowest possible difficulty
    target_limit: Uint256,
    /// Time interval in secs between the blocks targeted by the difficulty adjustment algorithm
    target_block_time: NonZeroU64,
    /// The distance required to pass to allow spending the block reward
    reward_maturity_distance: BlockDistance,
    /// The distance required to pass to allow spending the decommission pool
    decommission_maturity_distance: BlockDistance,
    /// Max number of blocks required to calculate average block time. Min is 2
    block_count_to_average_for_blocktime: usize,
}

impl PoSChainConfig {
    pub fn new(
        target_limit: Uint256,
        target_block_time: u64,
        reward_maturity_distance: BlockDistance,
        decommission_maturity_distance: BlockDistance,
        block_count_to_average_for_blocktime: usize,
    ) -> Option<Self> {
        let target_block_time = NonZeroU64::new(target_block_time)?;
        if block_count_to_average_for_blocktime < 2 {
            return None;
        }

        Some(Self {
            target_limit,
            target_block_time,
            reward_maturity_distance,
            decommission_maturity_distance,
            block_count_to_average_for_blocktime,
        })
    }

    pub fn target_limit(&self) -> Uint256 {
        self.target_limit
    }

    pub fn target_block_time(&self) -> NonZeroU64 {
        self.target_block_time
    }

    pub fn reward_maturity_distance(&self) -> BlockDistance {
        self.reward_maturity_distance
    }

    pub fn decommission_maturity_distance(&self) -> BlockDistance {
        self.decommission_maturity_distance
    }

    pub fn block_count_to_average_for_blocktime(&self) -> usize {
        self.block_count_to_average_for_blocktime
    }
}

pub fn create_unittest_pos_config() -> PoSChainConfig {
    PoSChainConfig {
        target_limit: Uint256::MAX,
        target_block_time: NonZeroU64::new(2 * 60).expect("cannot not be 0"),
        reward_maturity_distance: 2000.into(),
        decommission_maturity_distance: 2000.into(),
        block_count_to_average_for_blocktime: 5,
    }
}

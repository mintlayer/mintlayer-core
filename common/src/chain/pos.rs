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

use std::time::Duration;

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
    retargeting_enabled: bool,
    /// The lowest possible difficulty
    target_limit: Uint256,
    /// Time interval between the blocks targeted by the difficulty adjustment algorithm
    target_block_time: Duration,
    /// The distance required to pass to allow spending the block reward
    reward_maturity_distance: BlockDistance,
}

impl PoSChainConfig {
    pub fn new(
        retargeting_enabled: bool,
        target_limit: Uint256,
        target_block_time: Duration,
        reward_maturity_distance: BlockDistance,
    ) -> Self {
        Self {
            retargeting_enabled,
            target_limit,
            target_block_time,
            reward_maturity_distance,
        }
    }

    pub fn target_limit(&self) -> Uint256 {
        self.target_limit
    }

    pub fn target_block_time(&self) -> Duration {
        self.target_block_time
    }

    pub fn reward_maturity_distance(&self) -> BlockDistance {
        self.reward_maturity_distance
    }

    pub fn retargeting_enabled(&self) -> bool {
        self.retargeting_enabled
    }
}

// FIXME: find proper place for this
pub fn create_test_pos_config() -> PoSChainConfig {
    PoSChainConfig {
        retargeting_enabled: false,
        target_limit: Uint256::MAX,
        target_block_time: Duration::from_secs(2 * 60),
        reward_maturity_distance: 2000.into(),
    }
}

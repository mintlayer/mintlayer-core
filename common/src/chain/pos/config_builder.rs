// Copyright (c) 2023 RBB S.r.l
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

use crate::{
    primitives::{per_thousand::PerThousand, BlockDistance},
    Uint256,
};

use super::{config::PoSChainConfig, PoSConsensusVersion};

pub struct PoSChainConfigBuilder {
    target_limit: Uint256,
    target_block_time: NonZeroU64,
    decommission_maturity_distance: BlockDistance,
    spend_share_maturity_distance: BlockDistance,
    block_count_to_average_for_blocktime: usize,
    difficulty_change_limit: PerThousand,
    consensus_version: PoSConsensusVersion,
}

impl PoSChainConfigBuilder {
    pub fn new_for_unit_test() -> Self {
        Self {
            target_limit: Uint256::MAX,
            target_block_time: NonZeroU64::new(2 * 60).expect("cannot be 0"),
            decommission_maturity_distance: super::DEFAULT_MATURITY_DISTANCE,
            spend_share_maturity_distance: super::DEFAULT_MATURITY_DISTANCE,
            block_count_to_average_for_blocktime: super::DEFAULT_BLOCK_COUNT_TO_AVERAGE,
            difficulty_change_limit: PerThousand::new(1).expect("must be valid"),
            consensus_version: PoSConsensusVersion::V1,
        }
    }

    pub fn targe_limit(mut self, value: Uint256) -> Self {
        self.target_limit = value;
        self
    }

    pub fn targe_block_time(mut self, value: NonZeroU64) -> Self {
        self.target_block_time = value;
        self
    }

    pub fn decommission_maturity_distance(mut self, value: BlockDistance) -> Self {
        self.decommission_maturity_distance = value;
        self
    }

    pub fn spend_share_maturity_distance(mut self, value: BlockDistance) -> Self {
        self.spend_share_maturity_distance = value;
        self
    }

    pub fn block_count_to_average_for_blocktime(mut self, value: usize) -> Self {
        self.block_count_to_average_for_blocktime = value;
        self
    }

    pub fn difficulty_change_limit(mut self, value: PerThousand) -> Self {
        self.difficulty_change_limit = value;
        self
    }

    pub fn consensus_version(mut self, value: PoSConsensusVersion) -> Self {
        self.consensus_version = value;
        self
    }

    pub fn build(self) -> PoSChainConfig {
        PoSChainConfig::new(
            self.target_limit,
            self.target_block_time,
            self.decommission_maturity_distance,
            self.spend_share_maturity_distance,
            self.block_count_to_average_for_blocktime,
            self.difficulty_change_limit,
            self.consensus_version,
        )
    }
}

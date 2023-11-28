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

use crate::{
    primitives::{per_thousand::PerThousand, BlockCount},
    Uint256,
};

use super::PoSConsensusVersion;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PoSChainConfig {
    /// The lowest possible difficulty
    target_limit: Uint256,
    /// The distance required to pass to allow spending the decommission pool and spending delegation share
    staking_pool_spend_maturity_block_count: BlockCount,
    /// Max number of blocks required to calculate average block time. Min is 2
    block_count_to_average_for_blocktime: usize,
    /// The limit on how much the difficulty can go up or down after each block
    difficulty_change_limit: PerThousand,
    /// Version of the consensus protocol
    consensus_version: PoSConsensusVersion,
}

impl PoSChainConfig {
    pub fn new(
        target_limit: Uint256,
        staking_pool_spend_maturity_block_count: BlockCount,
        block_count_to_average_for_blocktime: usize,
        difficulty_change_limit: PerThousand,
        consensus_version: PoSConsensusVersion,
    ) -> Self {
        assert!(block_count_to_average_for_blocktime >= 2);

        Self {
            target_limit,
            staking_pool_spend_maturity_block_count,
            block_count_to_average_for_blocktime,
            difficulty_change_limit,
            consensus_version,
        }
    }

    pub fn target_limit(&self) -> Uint256 {
        self.target_limit
    }

    pub fn staking_pool_spend_maturity_block_count(&self) -> BlockCount {
        self.staking_pool_spend_maturity_block_count
    }

    pub fn block_count_to_average_for_blocktime(&self) -> usize {
        self.block_count_to_average_for_blocktime
    }

    pub fn difficulty_change_limit(&self) -> PerThousand {
        self.difficulty_change_limit
    }

    pub fn consensus_version(&self) -> PoSConsensusVersion {
        self.consensus_version
    }
}

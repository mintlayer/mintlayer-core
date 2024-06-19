// Copyright (c) 2021-2024 RBB S.r.l
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

use chainstate_types::pos_randomness::PoSRandomness;
use common::{
    chain::{block::timestamp::BlockTimestamp, config::EpochIndex, GenBlock, PoSChainConfig},
    primitives::{Amount, Id},
    Uint256,
};

/// This struct holds certain information necessary to produce a new block by staking.
#[derive(Debug, Clone)]
pub struct PoSBlockCandidateInfo {
    /// The information about the parent block.
    pub parent_id: Id<GenBlock>,
    pub parent_timestamp: BlockTimestamp,
    pub parent_chain_trust: Uint256,

    /// The target required for staking; this value depends on the parent block.
    pub target: Uint256,

    /// The PoS chain config corresponding to the height of the new block.
    pub pos_chain_config: PoSChainConfig,

    /// Epoch data corresponding to the height of the new block.
    pub epoch_index: EpochIndex,
    pub sealed_epoch_randomness: PoSRandomness,

    /// The balances of the pool that will be used for staking; these also depend ont he parent block.
    pub pool_staker_balance: Amount,
    pub pool_total_balance: Amount,
}

#[derive(Debug, Clone)]
pub struct PoSBlockCandidateInfoCmpByParentTS(pub PoSBlockCandidateInfo);

impl Ord for PoSBlockCandidateInfoCmpByParentTS {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by timestamps first; use the id to resolve ties.
        (self.0.parent_timestamp, self.0.parent_id)
            .cmp(&(other.0.parent_timestamp, other.0.parent_id))
    }
}

impl PartialOrd for PoSBlockCandidateInfoCmpByParentTS {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PoSBlockCandidateInfoCmpByParentTS {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for PoSBlockCandidateInfoCmpByParentTS {}

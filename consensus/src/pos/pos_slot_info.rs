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
    chain::{block::timestamp::BlockTimestamp, config::EpochIndex, PoSChainConfig},
    primitives::Amount,
    Uint256,
};

#[derive(Debug, Clone)]
pub struct PoSSlotInfo {
    pub parent_timestamp: BlockTimestamp,
    pub parent_chain_trust: Uint256,

    pub target: Uint256,
    pub pos_chain_config: PoSChainConfig,

    pub epoch_index: EpochIndex,
    pub sealed_epoch_randomness: PoSRandomness,

    pub staker_balance: Amount,
    pub total_balance: Amount,
}

#[derive(Debug, Clone)]
pub struct PoSSlotInfoCmpByParentTS<T: AsRef<PoSSlotInfo>>(pub T);

impl<T: AsRef<PoSSlotInfo>> Ord for PoSSlotInfoCmpByParentTS<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_ref().parent_timestamp.cmp(&other.0.as_ref().parent_timestamp)
    }
}

impl<T: AsRef<PoSSlotInfo>> PartialOrd for PoSSlotInfoCmpByParentTS<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: AsRef<PoSSlotInfo>> PartialEq for PoSSlotInfoCmpByParentTS<T> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl<T: AsRef<PoSSlotInfo>> Eq for PoSSlotInfoCmpByParentTS<T> {}

impl AsRef<PoSSlotInfo> for PoSSlotInfo {
    fn as_ref(&self) -> &PoSSlotInfo {
        self
    }
}

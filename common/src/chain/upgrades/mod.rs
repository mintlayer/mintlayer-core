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

mod consensus_upgrade;
mod netupgrade;

pub use consensus_upgrade::{ConsensusUpgrade, PoSStatus, PoWStatus, RequiredConsensus};
pub use netupgrade::NetUpgrades;

use crate::primitives::BlockHeight;

pub enum NetUpgradeError {
    GenerateConfigFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum NetUpgradeVersion {
    Genesis,
    PoS,
    PledgeIncentiveAndTokensSupply,
}

impl NetUpgradeVersion {
    pub fn is_activated(
        &self,
        height: BlockHeight,
        net_upgrade: &NetUpgrades<(NetUpgradeVersion, ConsensusUpgrade)>,
    ) -> bool {
        if let Ok(idx) = net_upgrade
            .all_upgrades()
            .binary_search_by(|(_, (to_match, _))| to_match.cmp(self))
        {
            return height >= net_upgrade.all_upgrades()[idx].0;
        }
        false
    }
}

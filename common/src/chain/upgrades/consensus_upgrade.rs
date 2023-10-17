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

use crate::chain::PoSChainConfig;
use crate::primitives::Compact;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum ConsensusUpgrade {
    PoW {
        initial_difficulty: Compact,
    },
    PoS {
        // If None the value will be taken from the network's current difficulty
        initial_difficulty: Option<Compact>,
        config: PoSChainConfig,
    },
    IgnoreConsensus,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum RequiredConsensus {
    PoW(PoWStatus),
    PoS(PoSStatus),
    IgnoreConsensus,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum PoWStatus {
    Ongoing,
    Threshold { initial_difficulty: Compact },
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum PoSStatus {
    Ongoing(PoSChainConfig),
    Threshold {
        // If None the value will be taken from the network's current difficulty
        initial_difficulty: Option<Compact>,
        config: PoSChainConfig,
    },
}

impl PoSStatus {
    pub fn get_chain_config(&self) -> &PoSChainConfig {
        match self {
            PoSStatus::Ongoing(config)
            | PoSStatus::Threshold {
                initial_difficulty: _,
                config,
            } => config,
        }
    }
}

impl From<ConsensusUpgrade> for RequiredConsensus {
    fn from(upgrade: ConsensusUpgrade) -> Self {
        match upgrade {
            ConsensusUpgrade::PoW { initial_difficulty } => {
                RequiredConsensus::PoW(PoWStatus::Threshold { initial_difficulty })
            }
            ConsensusUpgrade::PoS {
                initial_difficulty,
                config,
            } => RequiredConsensus::PoS(PoSStatus::Threshold {
                initial_difficulty,
                config,
            }),
            ConsensusUpgrade::IgnoreConsensus => RequiredConsensus::IgnoreConsensus,
        }
    }
}

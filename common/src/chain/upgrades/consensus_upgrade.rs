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

use crate::chain::config::ChainType;
use crate::chain::pos::{DEFAULT_BLOCK_COUNT_TO_AVERAGE, DEFAULT_MATURITY_BLOCK_COUNT_V0};
use crate::chain::pow::limit;
use crate::chain::{pos_initial_difficulty, PoSChainConfig, PoSConsensusVersion};
use crate::primitives::per_thousand::PerThousand;
use crate::primitives::{BlockHeight, Compact};
use crate::Uint256;

use super::NetUpgrades;

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

impl NetUpgrades<ConsensusUpgrade> {
    pub fn new_for_chain(chain_type: ChainType) -> Self {
        Self::initialize(vec![(
            BlockHeight::zero(),
            ConsensusUpgrade::PoW {
                initial_difficulty: limit(chain_type).into(),
            },
        )])
        .expect("cannot fail")
    }

    pub fn unit_tests() -> Self {
        Self::initialize(vec![(
            BlockHeight::zero(),
            ConsensusUpgrade::IgnoreConsensus,
        )])
        .expect("cannot fail")
    }

    #[cfg(test)]
    pub fn deliberate_ignore_consensus_twice() -> Self {
        Self::initialize(vec![
            (BlockHeight::zero(), ConsensusUpgrade::IgnoreConsensus),
            (BlockHeight::new(1), ConsensusUpgrade::IgnoreConsensus),
        ])
        .expect("cannot fail")
    }

    pub fn regtest_with_pos() -> Self {
        Self::regtest_with_pos_generic(
            BlockHeight::new(1),
            pos_initial_difficulty(ChainType::Regtest).into(),
        )
    }

    pub fn regtest_with_pos_generic(height: BlockHeight, initial_difficulty: Compact) -> Self {
        let target_limit = (Uint256::MAX / Uint256::from_u64(120))
            .expect("Target block time cannot be zero as per NonZeroU64");

        Self::initialize(vec![
            (BlockHeight::zero(), ConsensusUpgrade::IgnoreConsensus),
            (
                height,
                ConsensusUpgrade::PoS {
                    initial_difficulty: Some(initial_difficulty),
                    config: PoSChainConfig::new(
                        target_limit,
                        DEFAULT_MATURITY_BLOCK_COUNT_V0,
                        DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                        PerThousand::new(1).expect("must be valid"),
                        PoSConsensusVersion::V1,
                    ),
                },
            ),
        ])
        .expect("cannot fail")
    }

    pub fn consensus_status(&self, height: BlockHeight) -> RequiredConsensus {
        let (last_upgrade_height, last_consensus_upgrade) = self.version_at_height(height);

        match last_consensus_upgrade {
            ConsensusUpgrade::PoW { initial_difficulty } => {
                if *last_upgrade_height < height {
                    RequiredConsensus::PoW(PoWStatus::Ongoing)
                } else {
                    debug_assert_eq!(*last_upgrade_height, height);
                    RequiredConsensus::PoW(PoWStatus::Threshold {
                        initial_difficulty: *initial_difficulty,
                    })
                }
            }
            ConsensusUpgrade::PoS {
                initial_difficulty,
                config,
            } => {
                if *last_upgrade_height < height {
                    RequiredConsensus::PoS(PoSStatus::Ongoing(config.clone()))
                } else {
                    debug_assert_eq!(*last_upgrade_height, height);
                    RequiredConsensus::PoS(PoSStatus::Threshold {
                        initial_difficulty: *initial_difficulty,
                        config: config.clone(),
                    })
                }
            }
            ConsensusUpgrade::IgnoreConsensus => RequiredConsensus::IgnoreConsensus,
        }
    }
}

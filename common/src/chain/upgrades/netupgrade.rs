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

use std::ops::Range;

use crate::chain::config::ChainType;
use crate::chain::pow::limit;
use crate::chain::{
    pos_initial_difficulty, PoSChainConfig, PoSChainConfigBuilder, PoSConsensusVersion,
};
use crate::primitives::{BlockHeight, Compact};

#[derive(Debug, Clone)]
pub struct NetUpgrades<T>(Vec<(BlockHeight, T)>);

impl NetUpgrades<UpgradeVersion> {
    pub fn new(chain_type: ChainType) -> Self {
        Self(vec![(
            BlockHeight::zero(),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: limit(chain_type).into(),
            }),
        )])
    }

    pub fn unit_tests() -> Self {
        Self(vec![(
            BlockHeight::zero(),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        )])
    }

    #[cfg(test)]
    pub fn deliberate_ignore_consensus_twice() -> Self {
        Self(vec![
            (
                BlockHeight::zero(),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
            ),
            (
                BlockHeight::new(1),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
            ),
        ])
    }

    pub fn regtest_with_pos() -> Self {
        Self(vec![
            (
                BlockHeight::zero(),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
            ),
            (
                BlockHeight::new(1),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                    initial_difficulty: Some(pos_initial_difficulty(ChainType::Regtest).into()),
                    config: PoSChainConfigBuilder::new(ChainType::Regtest)
                        .consensus_version(PoSConsensusVersion::V1)
                        .build(),
                }),
            ),
        ])
    }

    pub fn all_upgrades(&self) -> &[(BlockHeight, UpgradeVersion)] {
        &self.0
    }
}

pub trait Activate {
    fn is_activated(&self, height: BlockHeight, net_upgrades: &NetUpgrades<Self>) -> bool
    where
        Self: Sized + Ord + Copy,
    {
        if let Ok(idx) = net_upgrades.0.binary_search_by(|&(_, to_match)| to_match.cmp(self)) {
            return height >= net_upgrades.0[idx].0;
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum UpgradeVersion {
    ConsensusUpgrade(ConsensusUpgrade),
    SomeUpgrade,
}

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

impl Activate for UpgradeVersion {}

#[derive(thiserror::Error, Debug)]
pub enum NetUpgradesInitializeError {
    #[error("Must be initialized with a non-empty vector of upgrades")]
    NoUpgrades,
    #[error("First upgrade must be at genesis")]
    FirstUpgradeNotAtGenesis,
}

impl<T: Ord> NetUpgrades<T> {
    pub fn initialize(upgrades: Vec<(BlockHeight, T)>) -> Result<Self, NetUpgradesInitializeError> {
        let mut upgrades = upgrades;
        upgrades.sort_unstable();

        match upgrades.first() {
            Some(&(height, _)) if height == BlockHeight::zero() => Ok(Self(upgrades)),
            Some(_) => Err(NetUpgradesInitializeError::FirstUpgradeNotAtGenesis),
            None => Err(NetUpgradesInitializeError::NoUpgrades),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn height_range(&self, version: &T) -> Option<Range<BlockHeight>> {
        self.0
            .iter()
            .enumerate()
            .find(|(_, (_, elem_version))| elem_version == version)
            .map(|(idx, &(start_h, _))| {
                let end_h = if (idx + 1) < self.0.len() {
                    self.0[idx + 1].0
                } else {
                    BlockHeight::max()
                };
                start_h..end_h
            })
    }

    pub fn version_at_height(&self, height: BlockHeight) -> Option<&(BlockHeight, T)> {
        self.0.iter().rev().find(|(upgrade_height, _)| *upgrade_height <= height)
    }
}

impl NetUpgrades<UpgradeVersion> {
    pub fn consensus_status(&self, height: BlockHeight) -> RequiredConsensus {
        let (last_upgrade_height, last_consensus_upgrade) = self
            .version_at_height(height)
            .and_then(|(upgrade_height, upgrade)| match upgrade {
                UpgradeVersion::ConsensusUpgrade(consensus_upgrade) => {
                    Some((upgrade_height, consensus_upgrade))
                }
                UpgradeVersion::SomeUpgrade => None,
            })
            .expect("Some consensus must have been set");

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::upgrades::netupgrade::NetUpgrades;
    use crate::chain::Activate;
    use crate::primitives::{BlockDistance, BlockHeight};
    use crate::Uint256;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
    pub enum MockVersion {
        Zero,
        One,
        Two,
        Three,
        Four,
        Five,
    }

    impl Activate for MockVersion {}

    fn mock_netupgrades() -> (NetUpgrades<MockVersion>, BlockHeight, BlockHeight) {
        let mut upgrades = vec![];
        let zero_height = BlockHeight::new(0);
        let two_height = BlockHeight::new(3500);
        let three_height = BlockHeight::new(80000);

        upgrades.push((zero_height, MockVersion::Zero));

        upgrades.push((three_height, MockVersion::Three));

        upgrades.push((BlockHeight::one(), MockVersion::One));

        upgrades.push((two_height, MockVersion::Two));

        (
            NetUpgrades::initialize(upgrades).expect("valid net upgrade"),
            two_height,
            three_height,
        )
    }

    #[test]
    fn check_is_activated() {
        let (upgrades, two_height, three_height) = mock_netupgrades();

        assert!(MockVersion::Two.is_activated(two_height, &upgrades));
        assert!(MockVersion::Two.is_activated(three_height, &upgrades));
        assert!(!MockVersion::Two.is_activated(BlockHeight::one(), &upgrades));
        assert!(!MockVersion::Two
            .is_activated((two_height - BlockDistance::new(1)).unwrap(), &upgrades));

        assert!(!MockVersion::Three.is_activated(two_height, &upgrades));
        assert!(!MockVersion::Three.is_activated(
            two_height.checked_add(10).expect("should be fine"),
            &upgrades
        ));
        assert!(MockVersion::Three.is_activated(three_height, &upgrades));
        assert!(MockVersion::Three.is_activated(BlockHeight::max(), &upgrades));
    }

    #[test]
    fn check_upgrade_versions() {
        assert_eq!(0u8, MockVersion::Zero as u8);
        assert_eq!(1u8, MockVersion::One as u8);
        assert_eq!(2u8, MockVersion::Two as u8);
        assert_eq!(3u8, MockVersion::Three as u8);
        assert_eq!(4u8, MockVersion::Four as u8);
        assert_eq!(5u8, MockVersion::Five as u8);
    }

    #[test]
    fn check_upgrade_height_range() {
        let (upgrades, two_height, three_height) = mock_netupgrades();

        let check = |vers_type: MockVersion, range: Range<BlockHeight>| {
            let res = upgrades.height_range(&vers_type);

            assert_eq!(Some(range), res);
        };

        check(MockVersion::Zero, BlockHeight::zero()..BlockHeight::one());
        check(MockVersion::One, BlockHeight::one()..two_height);
        check(MockVersion::Two, two_height..three_height);
        check(MockVersion::Three, three_height..BlockHeight::max());
    }

    #[test]
    fn check_version_at_height() {
        let (upgrades, two_height, three_height) = mock_netupgrades();

        let check = |height: BlockHeight, expected_version: MockVersion| {
            let res = upgrades.version_at_height(height).map(|(_, v)| v);

            assert_eq!(Some(&expected_version), res);
        };

        check(BlockHeight::zero(), MockVersion::Zero);
        check(BlockHeight::one(), MockVersion::One);
        check(BlockHeight::one().next_height(), MockVersion::One);
        check(two_height, MockVersion::Two);
        check(two_height.next_height(), MockVersion::Two);
        check(three_height, MockVersion::Three);
        check(three_height.next_height(), MockVersion::Three);
    }

    fn mock_consensus_upgrades() -> Result<NetUpgrades<UpgradeVersion>, NetUpgradesInitializeError>
    {
        let genesis_pow = BlockHeight::new(0);
        let first_pos_upgrade = BlockHeight::new(10_000);
        let back_to_pow = BlockHeight::new(15_000);

        let upgrades = vec![
            (
                genesis_pow,
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                    initial_difficulty: Uint256::from_u64(1000).into(),
                }),
            ),
            (
                first_pos_upgrade,
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                    initial_difficulty: Some(Uint256::from_u64(1500).into()),
                    config: PoSChainConfigBuilder::new_for_unit_test().build(),
                }),
            ),
            (
                back_to_pow,
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                    initial_difficulty: Uint256::from_u64(2000).into(),
                }),
            ),
        ];

        NetUpgrades::initialize(upgrades)
    }

    #[test]
    fn consensus_upgrade() {
        let upgrades = mock_consensus_upgrades().expect("valid netupgrades");
        assert_eq!(
            upgrades.consensus_status(0.into()),
            RequiredConsensus::PoW(PoWStatus::Threshold {
                initial_difficulty: Uint256::from_u64(1000).into()
            })
        );
        assert_eq!(
            upgrades.consensus_status(1.into()),
            RequiredConsensus::PoW(PoWStatus::Ongoing)
        );
        assert_eq!(
            upgrades.consensus_status(9_999.into()),
            RequiredConsensus::PoW(PoWStatus::Ongoing)
        );
        assert_eq!(
            upgrades.consensus_status(10_000.into()),
            RequiredConsensus::PoS(PoSStatus::Threshold {
                initial_difficulty: Some(Uint256::from_u64(1500).into()),
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },)
        );
        assert_eq!(
            upgrades.consensus_status(14_999.into()),
            RequiredConsensus::PoS(PoSStatus::Ongoing(
                PoSChainConfigBuilder::new_for_unit_test().build()
            ))
        );
        assert_eq!(
            upgrades.consensus_status(15_000.into()),
            RequiredConsensus::PoW(PoWStatus::Threshold {
                initial_difficulty: Uint256::from_u64(2_000).into()
            })
        );
        assert_eq!(
            upgrades.consensus_status(15_001.into()),
            RequiredConsensus::PoW(PoWStatus::Ongoing)
        );
    }
}

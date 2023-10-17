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

use itertools::Itertools;

use crate::chain::pos::{
    DEFAULT_BLOCK_COUNT_TO_AVERAGE, DEFAULT_MATURITY_DISTANCE, DEFAULT_TARGET_BLOCK_TIME,
};
use crate::chain::{pos_initial_difficulty, PoSChainConfig, PoSConsensusVersion};
use crate::primitives::per_thousand::PerThousand;
use crate::Uint256;
use crate::{
    chain::{config::ChainType, pow::limit},
    primitives::BlockHeight,
};

use super::{ConsensusUpgrade, NetUpgradeVersion, PoSStatus, PoWStatus, RequiredConsensus};

#[derive(Debug, Clone)]
pub struct NetUpgrades<T>(Vec<(BlockHeight, T)>);

#[derive(thiserror::Error, Debug)]
pub enum NetUpgradesInitializeError {
    #[error("Must be initialized with a non-empty vector of upgrades")]
    NoUpgrades,
    #[error("First upgrade must be at genesis")]
    FirstUpgradeNotAtGenesis,
    #[error("Upgrade versions must be sorted")]
    VersionsMustBeSorted,
}

impl<T: Ord> NetUpgrades<T> {
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

    pub fn version_at_height(&self, height: BlockHeight) -> &(BlockHeight, T) {
        self.0
            .iter()
            .rev()
            .find(|(upgrade_height, _)| *upgrade_height <= height)
            .expect("cannot happen if initialize was used to create NetUpgrade")
    }

    pub fn all_upgrades(&self) -> &[(BlockHeight, T)] {
        &self.0
    }
}

impl NetUpgrades<(NetUpgradeVersion, ConsensusUpgrade)> {
    pub fn initialize(
        upgrades: Vec<(BlockHeight, (NetUpgradeVersion, ConsensusUpgrade))>,
    ) -> Result<Self, NetUpgradesInitializeError> {
        let is_sorted = upgrades.iter().tuple_windows().all(
            |((left_height, (left_version, _)), (right_height, (right_version, _)))| {
                left_height <= right_height && left_version <= right_version
            },
        );
        if !is_sorted {
            return Err(NetUpgradesInitializeError::VersionsMustBeSorted);
        }

        match upgrades.first() {
            Some((height, (version, _)))
                if *height == BlockHeight::zero() && *version == NetUpgradeVersion::Genesis =>
            {
                Ok(Self(upgrades))
            }
            Some(_) => Err(NetUpgradesInitializeError::FirstUpgradeNotAtGenesis),
            None => Err(NetUpgradesInitializeError::NoUpgrades),
        }
    }

    pub fn unit_tests() -> Self {
        Self::initialize(vec![(
            BlockHeight::zero(),
            (
                NetUpgradeVersion::Genesis,
                ConsensusUpgrade::IgnoreConsensus,
            ),
        )])
        .expect("cannot fail")
    }

    pub fn unit_tests_with_pow() -> Self {
        Self::initialize(vec![(
            BlockHeight::zero(),
            (
                NetUpgradeVersion::Genesis,
                ConsensusUpgrade::PoW {
                    initial_difficulty: limit(ChainType::Mainnet).into(),
                },
            ),
        )])
        .expect("cannot fail")
    }

    pub fn regtest_with_pos() -> Self {
        let target_block_time = DEFAULT_TARGET_BLOCK_TIME;
        let target_limit = (Uint256::MAX / Uint256::from_u64(target_block_time.get()))
            .expect("Target block time cannot be zero as per NonZeroU64");

        Self::initialize(vec![
            (
                BlockHeight::zero(),
                (
                    NetUpgradeVersion::Genesis,
                    ConsensusUpgrade::IgnoreConsensus,
                ),
            ),
            (
                BlockHeight::new(1),
                (
                    NetUpgradeVersion::PoS,
                    ConsensusUpgrade::PoS {
                        initial_difficulty: Some(pos_initial_difficulty(ChainType::Regtest).into()),
                        config: PoSChainConfig::new(
                            target_limit,
                            target_block_time,
                            DEFAULT_MATURITY_DISTANCE,
                            DEFAULT_MATURITY_DISTANCE,
                            DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                            PerThousand::new(1).expect("must be valid"),
                            PoSConsensusVersion::V1,
                        ),
                    },
                ),
            ),
        ])
        .expect("cannot fail")
    }

    pub fn consensus_status(&self, height: BlockHeight) -> RequiredConsensus {
        let (last_upgrade_height, (_, last_consensus_upgrade)) = self.version_at_height(height);

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
    use crate::chain::{
        ConsensusUpgrade, PoSChainConfigBuilder, PoSStatus, PoWStatus, RequiredConsensus,
    };
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

    fn mock_netupgrades() -> (NetUpgrades<MockVersion>, BlockHeight, BlockHeight) {
        let mut upgrades = vec![];
        let zero_height = BlockHeight::new(0);
        let two_height = BlockHeight::new(3500);
        let three_height = BlockHeight::new(80000);

        upgrades.push((zero_height, MockVersion::Zero));
        upgrades.push((BlockHeight::one(), MockVersion::One));
        upgrades.push((two_height, MockVersion::Two));
        upgrades.push((three_height, MockVersion::Three));

        (NetUpgrades(upgrades), two_height, three_height)
    }

    #[test]
    fn check_is_activated() {
        let upgrades = mock_consensus_upgrades().expect("valid netupgrades");
        assert_eq!(upgrades.all_upgrades().len(), 3);
        let two_height = upgrades.all_upgrades()[1].0;
        let three_height = upgrades.all_upgrades()[2].0;

        assert!(NetUpgradeVersion::PoS.is_activated(two_height, &upgrades));
        assert!(NetUpgradeVersion::PoS.is_activated(three_height, &upgrades));
        assert!(!NetUpgradeVersion::PoS.is_activated(BlockHeight::one(), &upgrades));
        assert!(!NetUpgradeVersion::PoS
            .is_activated((two_height - BlockDistance::new(1)).unwrap(), &upgrades));

        assert!(
            !NetUpgradeVersion::PledgeIncentiveAndTokensSupply.is_activated(two_height, &upgrades)
        );
        assert!(
            !NetUpgradeVersion::PledgeIncentiveAndTokensSupply.is_activated(
                two_height.checked_add(10).expect("should be fine"),
                &upgrades
            )
        );
        assert!(
            NetUpgradeVersion::PledgeIncentiveAndTokensSupply.is_activated(three_height, &upgrades)
        );
        assert!(NetUpgradeVersion::PledgeIncentiveAndTokensSupply
            .is_activated(BlockHeight::max(), &upgrades));
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
            let (_, res) = upgrades.version_at_height(height);

            assert_eq!(&expected_version, res);
        };

        check(BlockHeight::zero(), MockVersion::Zero);
        check(BlockHeight::one(), MockVersion::One);
        check(BlockHeight::one().next_height(), MockVersion::One);
        check(two_height, MockVersion::Two);
        check(two_height.next_height(), MockVersion::Two);
        check(three_height, MockVersion::Three);
        check(three_height.next_height(), MockVersion::Three);
    }

    fn mock_consensus_upgrades(
    ) -> Result<NetUpgrades<(NetUpgradeVersion, ConsensusUpgrade)>, NetUpgradesInitializeError>
    {
        let genesis_pow = BlockHeight::new(0);
        let first_pos_upgrade = BlockHeight::new(10_000);
        let back_to_pow = BlockHeight::new(15_000);

        let upgrades = vec![
            (
                genesis_pow,
                (
                    NetUpgradeVersion::Genesis,
                    ConsensusUpgrade::PoW {
                        initial_difficulty: Uint256::from_u64(1000).into(),
                    },
                ),
            ),
            (
                first_pos_upgrade,
                (
                    NetUpgradeVersion::PoS,
                    ConsensusUpgrade::PoS {
                        initial_difficulty: Some(Uint256::from_u64(1500).into()),
                        config: PoSChainConfigBuilder::new_for_unit_test().build(),
                    },
                ),
            ),
            (
                back_to_pow,
                (
                    NetUpgradeVersion::PledgeIncentiveAndTokensSupply,
                    ConsensusUpgrade::PoW {
                        initial_difficulty: Uint256::from_u64(2000).into(),
                    },
                ),
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

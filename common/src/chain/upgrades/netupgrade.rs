#![allow(clippy::upper_case_acronyms, clippy::needless_doctest_main)]

use crate::chain::config::ChainType;
use crate::chain::pow::limit;
use crate::primitives::{BlockDistance, BlockHeight, Compact};

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
}

impl NetUpgrades<UpgradeVersion> {
    pub fn unit_tests() -> Self {
        Self(vec![(
            BlockHeight::zero(),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        )])
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum UpgradeVersion {
    ConsensusUpgrade(ConsensusUpgrade),
    SomeUpgrade,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum ConsensusUpgrade {
    PoW { initial_difficulty: Compact },
    PoS,
    DSA,
    IgnoreConsensus,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum RequiredConsensus {
    // Either genesis or previous block was not PoW
    PoW(PoWStatus),
    PoS,
    DSA,
    IgnoreConsensus,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum PoWStatus {
    Ongoing,
    Threshold { initial_difficulty: Compact },
}

impl From<ConsensusUpgrade> for RequiredConsensus {
    fn from(upgrade: ConsensusUpgrade) -> Self {
        match upgrade {
            ConsensusUpgrade::PoW { initial_difficulty } => {
                RequiredConsensus::PoW(PoWStatus::Threshold { initial_difficulty })
            }
            ConsensusUpgrade::PoS => RequiredConsensus::PoS,
            ConsensusUpgrade::DSA => RequiredConsensus::DSA,
            ConsensusUpgrade::IgnoreConsensus => RequiredConsensus::IgnoreConsensus,
        }
    }
}

impl Activate for UpgradeVersion {}

impl<T: Ord + Copy> NetUpgrades<T> {
    #[allow(dead_code)]
    pub fn initialize(upgrades: Vec<(BlockHeight, T)>) -> anyhow::Result<Self> {
        let mut upgrades = upgrades;
        upgrades.sort_unstable();

        match upgrades.first() {
            Some(&(height, _)) if height == BlockHeight::zero() =>
                Ok(Self(upgrades)),
                _ =>
                Err(anyhow::Error::msg("NetUpgrades must be initialized with a nonempty vector of upgrades with an upgrade at genesis"))
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn height_range(&self, version: T) -> Option<(BlockHeight, BlockHeight)> {
        let res = self
            .0
            .iter()
            .enumerate()
            .find(|&(_, &(_, elem_version))| elem_version == version);

        res.map(|(idx, &(start_h, _))| {
            (
                start_h,
                if idx == (self.0.len() - 1) {
                    BlockHeight::max()
                } else {
                    (self.0[idx + 1].0 - BlockDistance::new(1)).expect(
                        "Upgrade heights should never overflow/underflow as they're chosen by us",
                    )
                },
            )
        })
    }
}

impl NetUpgrades<UpgradeVersion> {
    pub fn consensus_status(&self, height: BlockHeight) -> RequiredConsensus {
        let (last_upgrade_height, last_consensus_upgrade) = self
            .0
            .iter()
            .rev()
            .filter(|(block_height, _upgrade)| *block_height <= height)
            .find_map(|(block_height, upgrade)| {
                if let UpgradeVersion::ConsensusUpgrade(consensus_upgrade) = upgrade {
                    Some((block_height, consensus_upgrade))
                } else {
                    None
                }
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
            ConsensusUpgrade::PoS => RequiredConsensus::PoS,
            ConsensusUpgrade::DSA => RequiredConsensus::DSA,
            ConsensusUpgrade::IgnoreConsensus => RequiredConsensus::IgnoreConsensus,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::upgrades::netupgrade::NetUpgrades;
    use crate::chain::Activate;
    use crate::primitives::BlockHeight;
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

        let check = |vers_type: MockVersion, height: BlockHeight, end_range: BlockHeight| {
            let res = upgrades.height_range(vers_type);

            assert_eq!(Some((height, end_range)), res);
        };

        check(MockVersion::Zero, BlockHeight::zero(), BlockHeight::zero());
        check(
            MockVersion::One,
            BlockHeight::one(),
            (two_height - BlockDistance::new(1)).unwrap(),
        );
        check(
            MockVersion::Two,
            two_height,
            (three_height - BlockDistance::new(1)).unwrap(),
        );
        check(MockVersion::Three, three_height, BlockHeight::max());
    }

    fn mock_consensus_upgrades() -> anyhow::Result<NetUpgrades<UpgradeVersion>> {
        let genesis_pow = BlockHeight::new(0);
        let first_pos_upgrade = BlockHeight::new(10_000);
        let back_to_pow = BlockHeight::new(15_000);

        let upgrades = vec![
            (
                genesis_pow,
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                    initial_difficulty: Uint256::from_u64(1000).unwrap().into(),
                }),
            ),
            (
                first_pos_upgrade,
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS),
            ),
            (
                back_to_pow,
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                    initial_difficulty: Uint256::from_u64(2000).unwrap().into(),
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
                initial_difficulty: Uint256::from_u64(1000).unwrap().into()
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
            RequiredConsensus::PoS
        );
        assert_eq!(
            upgrades.consensus_status(14_999.into()),
            RequiredConsensus::PoS
        );
        assert_eq!(
            upgrades.consensus_status(15_000.into()),
            RequiredConsensus::PoW(PoWStatus::Threshold {
                initial_difficulty: Uint256::from_u64(2_000).unwrap().into()
            })
        );
        assert_eq!(
            upgrades.consensus_status(15_001.into()),
            RequiredConsensus::PoW(PoWStatus::Ongoing)
        );
    }
}

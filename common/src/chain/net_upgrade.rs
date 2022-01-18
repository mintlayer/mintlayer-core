#![allow(clippy::upper_case_acronyms)]

use crate::chain::config::ChainType;
use crate::chain::pow::POWConfig;
use crate::primitives::height::Saturating;
use crate::primitives::BlockHeight;
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

pub type NetUpgradeVersion = u8;
pub type NetUpgrades = BTreeMap<BlockHeight, NetUpgradeVersionType>;

#[derive(Debug, PartialEq, Eq)]
enum NetVersion {
    Genesis = 0,
    ChangeConsensus = 1,
    DSA = 3,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum NetUpgradeVersionType {
    Genesis,
    DSA,
    POW,
    POS,
}
impl NetUpgradeVersionType {
    fn get_version_num(&self) -> NetUpgradeVersion {
        match self {
            NetUpgradeVersionType::Genesis => NetVersion::Genesis as NetUpgradeVersion,
            NetUpgradeVersionType::DSA => NetVersion::DSA as NetUpgradeVersion,
            NetUpgradeVersionType::POW | NetUpgradeVersionType::POS => {
                NetVersion::ChangeConsensus as NetUpgradeVersion
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetUpgradeConfig {
    Genesis,
    DSA, // TODO: this should be a struct, defined somewhere else

    // Can add more different "versions" for other consensus.
    // But for the NetUpgradeVersion, they will all be considered as Version 1.
    // The difference will be found in the NetConfig.
    POS, // TODO: this should be a struct, defined somewhere else
    POW(POWConfig),
}

impl NetUpgradeConfig {
    pub fn get_version_type(&self) -> NetUpgradeVersionType {
        match self {
            NetUpgradeConfig::Genesis => NetUpgradeVersionType::Genesis,
            NetUpgradeConfig::DSA => NetUpgradeVersionType::DSA,
            NetUpgradeConfig::POS => NetUpgradeVersionType::POS,
            NetUpgradeConfig::POW(_) => NetUpgradeVersionType::POW,
        }
    }

    pub fn get_version_num(&self) -> NetUpgradeVersion {
        self.get_version_type().get_version_num()
    }

    pub fn generate(net_version: NetUpgradeVersionType, chain_type: ChainType) -> Option<Self> {
        match net_version {
            NetUpgradeVersionType::POW => Some(NetUpgradeConfig::POW(POWConfig::from(chain_type))),
            NetUpgradeVersionType::POS => Some(NetUpgradeConfig::POS),
            NetUpgradeVersionType::DSA => Some(NetUpgradeConfig::DSA),
            NetUpgradeVersionType::Genesis => None,
        }
    }
}

pub trait NetUpgradesExt {
    fn is_upgrade_activated(&self, height: BlockHeight) -> bool;
    fn version_num_from_height(&self, height: BlockHeight) -> NetUpgradeVersion;
    fn version_type_from_height(&self, height: BlockHeight) -> NetUpgradeVersionType;
    fn height_range(&self, version_type: NetUpgradeVersionType) -> Vec<(BlockHeight, BlockHeight)>;
}

impl NetUpgradesExt for NetUpgrades {
    fn is_upgrade_activated(&self, height: BlockHeight) -> bool {
        self.contains_key(&height)
    }

    fn version_num_from_height(&self, height: BlockHeight) -> NetUpgradeVersion {
        self.version_type_from_height(height).get_version_num()
    }

    fn version_type_from_height(&self, height: BlockHeight) -> NetUpgradeVersionType {
        if let Some(net_upgrade) = self.get(&height) {
            *net_upgrade
        }
        // just get the consensus config of the nearest given height.
        else {
            let mut new_range = self.range((Unbounded, Excluded(height)));
            match new_range.next_back() {
                None => NetUpgradeVersionType::Genesis,
                Some((_, vers_type)) => *vers_type,
            }
        }
    }

    fn height_range(&self, version_type: NetUpgradeVersionType) -> Vec<(BlockHeight, BlockHeight)> {
        if version_type == NetUpgradeVersionType::Genesis {
            return vec![(BlockHeight::zero(), BlockHeight::zero())];
        }

        let mut result: Vec<(BlockHeight, BlockHeight)> = vec![];

        let h_zero = BlockHeight::zero();
        let mut start = h_zero;

        // For every new element, check if it matches the version_type.
        self.iter().for_each(|(elem_height, elem_version)| {
            if *elem_version == version_type {
                // if a match is found for the first time, set it as the "start" of the range.
                if start == h_zero {
                    start = *elem_height;
                }
            }
            // If the current element is a new version, and the start of the range was set,
            // then the block height before this element is the "end" of the range.
            else if start > h_zero {
                result.push((start, elem_height.saturating_sub(1)));

                // reset back to zero, indicating that a new range is ready.
                start = h_zero;
            }
        });

        // If a start of a range was set, it means this version_type is the current and active version.
        // Set the "end" of the range to the maximum block height.
        if start > h_zero {
            result.push((start, BlockHeight::max()));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::config::ChainType;
    use crate::chain::{
        NetUpgradeConfig, NetUpgradeVersion, NetUpgradeVersionType, NetUpgrades, NetUpgradesExt,
        POWConfig,
    };
    use crate::primitives::height::Saturating;
    use crate::primitives::BlockHeight;

    fn mock_netupgrades() -> (NetUpgrades, BlockHeight, BlockHeight) {
        let mut upgrades = NetUpgrades::new();
        let pos_height = BlockHeight::new(350);
        let dsa_height = BlockHeight::new(3000);

        upgrades.insert(BlockHeight::zero(), NetUpgradeVersionType::Genesis);

        upgrades.insert(BlockHeight::one(), NetUpgradeVersionType::POW);

        upgrades.insert(pos_height, NetUpgradeVersionType::POS);

        upgrades.insert(dsa_height, NetUpgradeVersionType::DSA);

        (upgrades, pos_height, dsa_height)
    }

    #[test]
    fn check_upgrade_activated() {
        let (upgrades, pos_height, dsa_height) = mock_netupgrades();

        let is_activated = |h: BlockHeight| {
            assert!(&upgrades.is_upgrade_activated(h));
        };

        let not_activated = |h: BlockHeight| {
            assert!(!&upgrades.is_upgrade_activated(h));
        };

        is_activated(BlockHeight::zero());
        is_activated(BlockHeight::one());
        is_activated(pos_height);
        is_activated(dsa_height);

        not_activated(BlockHeight::new(2));
        not_activated(BlockHeight::new(100));
        not_activated(pos_height.saturating_add(1));
        not_activated(pos_height.saturating_add(2));
        not_activated(pos_height.saturating_sub(1));
        not_activated(pos_height.saturating_sub(2));
        not_activated(dsa_height.saturating_add(2));
        not_activated(dsa_height.saturating_add(1));
        not_activated(dsa_height.saturating_sub(1));
        not_activated(dsa_height.saturating_sub(2));
    }

    #[test]
    fn check_upgrade_version_from_height() {
        let (upgrades, pos_height, dsa_height) = mock_netupgrades();

        let check = |v: &NetUpgradeVersion, h: BlockHeight| {
            assert_eq!(v, &upgrades.version_num_from_height(h));
        };

        check(&0, BlockHeight::zero());
        check(&1, BlockHeight::one()); // POW is version 1
        check(&1, BlockHeight::new(26)); // POW is version 1
        check(&1, pos_height); // POS is version 1
        check(&1, pos_height.saturating_add(1)); // POS is version 1
        check(&1, dsa_height.saturating_sub(1));
        check(&3, dsa_height);
        check(&3, dsa_height.saturating_add(100));
        check(&3, dsa_height.saturating_add(2022));
        check(&3, dsa_height.saturating_add(3000));
    }

    #[test]
    fn check_upgrade_versions() {
        assert_eq!(0, NetUpgradeVersionType::Genesis.get_version_num());
        assert_eq!(1, NetUpgradeVersionType::POW.get_version_num());
        assert_eq!(1, NetUpgradeVersionType::POS.get_version_num());
        assert_eq!(3, NetUpgradeVersionType::DSA.get_version_num());
    }

    #[test]
    fn check_upgrade_height_range() {
        let (upgrades, pos_height, dsa_height) = mock_netupgrades();

        let check =
            |vers_type: NetUpgradeVersionType, height: BlockHeight, end_range: BlockHeight| {
                let res = upgrades.height_range(vers_type);
                assert_eq!(1, res.len());

                assert_eq!(
                    &(height, end_range),
                    res.first().expect("this should have one value inside")
                );
            };

        check(
            NetUpgradeVersionType::Genesis,
            BlockHeight::zero(),
            BlockHeight::zero(),
        );
        check(
            NetUpgradeVersionType::POW,
            BlockHeight::one(),
            pos_height.saturating_sub(1),
        );
        check(
            NetUpgradeVersionType::POS,
            pos_height,
            dsa_height.saturating_sub(1),
        );
        check(NetUpgradeVersionType::DSA, dsa_height, BlockHeight::max());
    }

    #[test]
    fn check_upgrade_config() {
        fn pow(chain_type: ChainType) {
            let cfg = NetUpgradeConfig::generate(NetUpgradeVersionType::POW, chain_type);
            assert!(cfg.is_some());
            let cfg = cfg.expect("should have value");

            assert_eq!(NetUpgradeConfig::POW(POWConfig::from(chain_type)), cfg);
        }

        pow(ChainType::Mainnet);
        pow(ChainType::Testnet);
        pow(ChainType::Signet);
        pow(ChainType::Regtest);

        fn genesis(chain_type: ChainType) {
            assert!(
                NetUpgradeConfig::generate(NetUpgradeVersionType::Genesis, chain_type).is_none()
            );
        }

        genesis(ChainType::Mainnet);
        genesis(ChainType::Testnet);
        genesis(ChainType::Signet);
        genesis(ChainType::Regtest);
    }
}

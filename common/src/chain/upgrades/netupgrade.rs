#![allow(clippy::upper_case_acronyms)]

use crate::primitives::height::Saturating;
use crate::primitives::BlockHeight;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
#[repr(u8)]
pub enum UpgradeVersion {
    Genesis = 0,
    POW,
    POS,
    DSA = 5,
}

#[derive(Debug, Clone)]
pub struct NetUpgrade(Vec<(BlockHeight, UpgradeVersion)>);

impl Default for NetUpgrade {
    fn default() -> Self {
        Self(vec![(BlockHeight::zero(), UpgradeVersion::Genesis)])
    }
}

impl NetUpgrade {
    #[allow(dead_code)]
    pub(crate) fn initialize(upgrades: Vec<(BlockHeight, UpgradeVersion)>) -> Self {
        let mut upgrades = upgrades;
        upgrades.sort();

        if let Some(&(height, _)) = upgrades.first() {
            return if height == BlockHeight::zero() {
                Self(upgrades)
            } else {
                let mut default: NetUpgrade = Default::default();
                default.0.append(&mut upgrades);
                default
            };
        }

        NetUpgrade::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_upgrade_activated(&self, height: BlockHeight) -> bool {
        #![allow(clippy::search_is_some)]
        self.0.iter().find(|&(elem_height, _)| *elem_height == height).is_some()
    }

    pub fn get_version(&self, height: BlockHeight) -> UpgradeVersion {
        match self.0.iter().rfind(|&&(elem_height, _)| elem_height <= height) {
            None => UpgradeVersion::Genesis,
            Some(&(_, version)) => version,
        }
    }

    pub fn height_range(&self, version: UpgradeVersion) -> Option<(BlockHeight, BlockHeight)> {
        self.0
            .iter()
            .enumerate()
            .find(|&(_, &(_, elem_version))| elem_version == version)
            .map(|(idx, &(start_h, _))| {
                (
                    start_h,
                    if idx == (self.0.len() - 1) {
                        BlockHeight::max()
                    } else {
                        self.0[idx + 1].0.saturating_sub(1)
                    },
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::upgrades::netupgrade::{NetUpgrade, UpgradeVersion};
    use crate::primitives::height::Saturating;
    use crate::primitives::BlockHeight;

    fn mock_netupgrades() -> (NetUpgrade, BlockHeight, BlockHeight) {
        let mut upgrades = vec![];
        let pos_height = BlockHeight::new(350);
        let dsa_height = BlockHeight::new(3000);

        upgrades.push((BlockHeight::one(), UpgradeVersion::POW));

        upgrades.push((pos_height, UpgradeVersion::POS));

        upgrades.push((dsa_height, UpgradeVersion::DSA));

        (NetUpgrade::initialize(upgrades), pos_height, dsa_height)
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

        println!("THE UPGRADES: {:?}", upgrades);

        let check = |v: UpgradeVersion, h: BlockHeight| {
            assert_eq!(v, upgrades.get_version(h));
        };

        check(UpgradeVersion::Genesis, BlockHeight::zero());
        check(UpgradeVersion::POW, BlockHeight::one());
        check(UpgradeVersion::POW, BlockHeight::new(26));
        check(UpgradeVersion::POW, pos_height.saturating_sub(1));
        check(UpgradeVersion::POS, pos_height);
        check(UpgradeVersion::POS, pos_height.saturating_add(1));
        check(UpgradeVersion::POS, dsa_height.saturating_sub(1));
        check(UpgradeVersion::DSA, dsa_height);
        check(UpgradeVersion::DSA, dsa_height.saturating_add(100));
        check(UpgradeVersion::DSA, dsa_height.saturating_add(2022));
        check(UpgradeVersion::DSA, dsa_height.saturating_add(3000));
    }

    #[test]
    fn check_upgrade_versions() {
        assert_eq!(0u8, UpgradeVersion::Genesis as u8);
        assert_eq!(1u8, UpgradeVersion::POW as u8);
        assert_eq!(2u8, UpgradeVersion::POS as u8);
        assert_eq!(5u8, UpgradeVersion::DSA as u8);
    }

    #[test]
    fn check_upgrade_height_range() {
        let (upgrades, pos_height, dsa_height) = mock_netupgrades();

        let check = |vers_type: UpgradeVersion, height: BlockHeight, end_range: BlockHeight| {
            let res = upgrades.height_range(vers_type);

            assert_eq!(Some((height, end_range)), res);
        };

        check(
            UpgradeVersion::Genesis,
            BlockHeight::zero(),
            BlockHeight::zero(),
        );
        check(
            UpgradeVersion::POW,
            BlockHeight::one(),
            pos_height.saturating_sub(1),
        );
        check(
            UpgradeVersion::POS,
            pos_height,
            dsa_height.saturating_sub(1),
        );
        check(UpgradeVersion::DSA, dsa_height, BlockHeight::max());
    }
}

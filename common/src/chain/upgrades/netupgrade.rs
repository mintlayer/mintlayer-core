#![allow(clippy::upper_case_acronyms)]

use crate::primitives::height::Saturating;
use crate::primitives::BlockHeight;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

pub type UpgradeVersionNum = u8;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum UpgradeVersion {
    Genesis = 0,
    POW,
    POS,
    DSA = 5,
}

#[derive(Debug, Clone)]
pub struct NetUpgrade(BTreeMap<BlockHeight, UpgradeVersionNum>);

impl Default for NetUpgrade {
    fn default() -> Self {
        let mut height_to_version = BTreeMap::<BlockHeight, UpgradeVersionNum>::new();
        height_to_version.insert(BlockHeight::zero(), UpgradeVersion::Genesis.into());

        Self(height_to_version)
    }
}

impl NetUpgrade {
    pub fn insert(
        &mut self,
        height: BlockHeight,
        version: UpgradeVersion,
    ) -> Option<UpgradeVersionNum> {
        self.0.insert(height, version.into())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_upgrade_activated(&self, height: BlockHeight) -> bool {
        self.0.contains_key(&height)
    }

    pub fn get_version(&self, height: BlockHeight) -> UpgradeVersion {
        if let Some(version) = self.0.get(&height) {
            UpgradeVersion::try_from(*version).expect("version number should be found in the enum")
        }
        // just get the consensus config of the nearest given height.
        else {
            let mut new_range = self.0.range((Unbounded, Excluded(height)));

            match new_range.next_back() {
                None => UpgradeVersion::Genesis,
                Some((_, version)) => UpgradeVersion::try_from(*version)
                    .expect("version number should be found in the enum"),
            }
        }
    }

    pub fn height_range(&self, version: UpgradeVersion) -> Vec<(BlockHeight, BlockHeight)> {
        if version == UpgradeVersion::Genesis {
            return vec![(BlockHeight::zero(), BlockHeight::zero())];
        }

        let mut result: Vec<(BlockHeight, BlockHeight)> = vec![];

        let h_zero = BlockHeight::zero();
        let mut start = h_zero;

        // For every new element, check if it matches the version_type.
        self.0.iter().for_each(|(elem_height, elem_version)| {
            if *elem_version == version.into() {
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
    use crate::chain::upgrades::netupgrade::{NetUpgrade, UpgradeVersion};
    use crate::primitives::height::Saturating;
    use crate::primitives::BlockHeight;
    use std::collections::BTreeMap;

    fn mock_netupgrades() -> (NetUpgrade, BlockHeight, BlockHeight) {
        let mut upgrades = NetUpgrade(BTreeMap::new());

        let pos_height = BlockHeight::new(350);
        let dsa_height = BlockHeight::new(3000);

        upgrades.insert(BlockHeight::zero(), UpgradeVersion::Genesis);

        upgrades.insert(BlockHeight::one(), UpgradeVersion::POW);

        upgrades.insert(pos_height, UpgradeVersion::POS);

        upgrades.insert(dsa_height, UpgradeVersion::DSA);

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

        let check = |v: UpgradeVersion, h: BlockHeight| {
            assert_eq!(upgrades.get_version(h), v);
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
        assert_eq!(0u8, UpgradeVersion::Genesis.into());
        assert_eq!(1u8, UpgradeVersion::POW.into());
        assert_eq!(2u8, UpgradeVersion::POS.into());
        assert_eq!(5u8, UpgradeVersion::DSA.into());
    }

    #[test]
    fn check_upgrade_height_range() {
        let (upgrades, pos_height, dsa_height) = mock_netupgrades();

        let check = |vers_type: UpgradeVersion, height: BlockHeight, end_range: BlockHeight| {
            let res = upgrades.height_range(vers_type);
            assert_eq!(1, res.len());

            assert_eq!(
                &(height, end_range),
                res.first().expect("this should have one value inside")
            );
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

#![allow(clippy::upper_case_acronyms, clippy::needless_doctest_main)]

use crate::primitives::height::Saturating;
use crate::primitives::BlockHeight;

#[derive(Debug, Clone)]
pub struct NetUpgrades<T>(Vec<(BlockHeight, T)>);

impl<T: Default> Default for NetUpgrades<T> {
    fn default() -> Self {
        Self(vec![(BlockHeight::zero(), T::default())])
    }
}

/// creates a function in NetUpgrades to check whether a certain upgrade is activated.
///
/// # Examples
/// ```
/// #[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
/// pub enum ConsensusConfig {
///    PoW, PoS, NPoS, DPos
/// }
///
/// is_activated_fn!(NPoS, ConsensusConfig, ConsensusConfig::NPoS);
///
/// fn main() {
///     let x = NetUpgrades::default();
///     x.is_NPoS_activated(); // this will return false
///     x.is_PoS_activated(); // compile error because function does not exist.
/// }
/// ```
/// ```
macro_rules! is_activated_fn {
    ($name:ident, $enum_ty:ty, $matcher:expr) => {
        impl NetUpgrades<$enum_ty> {
            paste::paste! {
                pub fn [< is_ $name _activated >](&self, height:BlockHeight) -> bool {
                    if let Ok(idx) = self.0.binary_search_by(|&(_,to_match)| {
                        to_match.cmp(&$matcher)
                    }) {

                        return height >= self.0[idx].0;
                    }

                    false
                }
            }
        }
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum UpgradeVersion {
    Genesis = 0,
    PoW,
    PoS,
    DSA,
}

impl Default for UpgradeVersion {
    fn default() -> Self {
        Self::Genesis
    }
}

// is_dsa_activated(block_height:BlockHeight)
is_activated_fn!(dsa, UpgradeVersion, UpgradeVersion::DSA);

impl<T: Default + Ord + Copy> NetUpgrades<T> {
    #[allow(dead_code)]
    pub(crate) fn initialize(upgrades: Vec<(BlockHeight, T)>) -> Self {
        let mut upgrades = upgrades;
        upgrades.sort();

        if let Some(&(height, _)) = upgrades.first() {
            return if height == BlockHeight::zero() {
                Self(upgrades)
            } else {
                let mut default = Self::default();
                default.0.append(&mut upgrades);
                default
            };
        }

        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get_version(&self, height: BlockHeight) -> T {
        match self.0.iter().rfind(|&&(elem_height, _)| elem_height <= height) {
            None => T::default(),
            Some(&(_, version)) => version,
        }
    }

    pub fn height_range(&self, version: T) -> Option<(BlockHeight, BlockHeight)> {
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
    use crate::chain::upgrades::netupgrade::NetUpgrades;
    use crate::primitives::height::Saturating;
    use crate::primitives::BlockHeight;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
    pub enum MockVersion {
        Zero,
        One,
        Two,
        Three,
        Four,
        Five,
    }

    impl Default for MockVersion {
        fn default() -> Self {
            Self::Zero
        }
    }

    is_activated_fn!(two, MockVersion, MockVersion::Two);

    fn mock_netupgrades() -> (NetUpgrades<MockVersion>, BlockHeight, BlockHeight) {
        let mut upgrades = vec![];
        let two_height = BlockHeight::new(3500);
        let three_height = BlockHeight::new(80000);

        upgrades.push((BlockHeight::one(), MockVersion::One));

        upgrades.push((two_height, MockVersion::Two));

        upgrades.push((three_height, MockVersion::Three));

        (NetUpgrades::initialize(upgrades), two_height, three_height)
    }

    #[test]
    fn check_is_activated() {
        let (upgrades, two_height, three_height) = mock_netupgrades();

        assert!(upgrades.is_two_activated(two_height));
        assert!(upgrades.is_two_activated(three_height));
        assert!(!upgrades.is_two_activated(BlockHeight::one()));
        assert!(!upgrades.is_two_activated(two_height.saturating_sub(1)));

        is_activated_fn!(three, MockVersion, MockVersion::Three);

        assert!(!upgrades.is_three_activated(two_height));
        assert!(!upgrades.is_three_activated(two_height.saturating_add(10)));
        assert!(upgrades.is_three_activated(three_height));
        assert!(upgrades.is_three_activated(BlockHeight::max()));
    }

    #[test]
    fn check_upgrade_version_from_height() {
        let (upgrades, two_height, three_height) = mock_netupgrades();

        let check = |v: MockVersion, h: BlockHeight| {
            assert_eq!(v, upgrades.get_version(h));
        };

        check(MockVersion::Zero, BlockHeight::zero());
        check(MockVersion::One, BlockHeight::one());
        check(MockVersion::One, BlockHeight::new(26));
        check(MockVersion::One, two_height.saturating_sub(1));
        check(MockVersion::Two, two_height);
        check(MockVersion::Two, two_height.saturating_add(1));
        check(MockVersion::Two, three_height.saturating_sub(1));
        check(MockVersion::Three, three_height);
        check(MockVersion::Three, three_height.saturating_add(100));
        check(MockVersion::Three, three_height.saturating_add(2022));
        check(MockVersion::Three, three_height.saturating_add(3000));
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
            two_height.saturating_sub(1),
        );
        check(MockVersion::Two, two_height, three_height.saturating_sub(1));
        check(MockVersion::Three, three_height, BlockHeight::max());
    }
}

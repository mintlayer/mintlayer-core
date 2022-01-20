#![allow(clippy::upper_case_acronyms)]


use common::primitives::BlockHeight;

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
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_upgrade_activated(&self, height: BlockHeight) -> bool {
       todo!()
    }

    pub fn get_version(&self, height: BlockHeight) -> UpgradeVersion {
        todo!()
    }

    pub fn height_range(&self, version: UpgradeVersion) -> Option<(BlockHeight, BlockHeight)> {
        todo!()
    }
}
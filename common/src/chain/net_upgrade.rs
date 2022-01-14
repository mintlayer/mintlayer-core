use crate::chain::config::ChainType;
use crate::chain::pow::POWConfig;
use crate::primitives::height::Saturating;
use crate::primitives::BlockHeight;
use std::collections::BTreeMap;
use std::ops::Bound::Included;

pub type NetUpgradeVersion = u8;
pub type NetUpgrades = BTreeMap<BlockHeight, Option<NetUpgradeConfig>>;

#[derive(Debug, PartialEq, Eq)]
enum NetVersion {
    Genesis = 0,
    ChangeConsensus = 1,
    DSA = 3,
}

#[derive(Debug, PartialEq, Eq)]
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

    pub fn create(net_version: NetUpgradeVersionType, chain_type: ChainType) -> Option<Self> {
        match net_version {
            NetUpgradeVersionType::POW => Some(NetUpgradeConfig::POW(POWConfig::from(chain_type))),
            NetUpgradeVersionType::POS => Some(NetUpgradeConfig::POS),
            NetUpgradeVersionType::DSA => Some(NetUpgradeConfig::DSA),
            NetUpgradeVersionType::Genesis => None,
        }
    }
}

pub trait NetUpgradesExt {
    fn is_upgrade_activated(&self, height: &BlockHeight) -> bool;
    fn get_net_config(&self, height: &BlockHeight) -> Option<NetUpgradeConfig>;
    fn get_version_num_from_height(&self, height: &BlockHeight) -> NetUpgradeVersion;
}

impl NetUpgradesExt for NetUpgrades {
    fn is_upgrade_activated(&self, height: &BlockHeight) -> bool {
        self.contains_key(height)
    }

    fn get_net_config(&self, height: &BlockHeight) -> Option<NetUpgradeConfig> {
        if let Some(net_upgrade) = self.get(height) {
            *net_upgrade
        }
        // just get the consensus config of the nearest given height.
        else {
            let mut min_height = *height;
            loop {
                let max_height = min_height.saturating_sub(1);

                //Note: it doesn't have to be 100. Could be 1000, or 10000
                min_height = min_height.saturating_sub(100);

                if max_height <= BlockHeight::one() {
                    // we've reached the lowest height of the chain.
                    return None;
                }

                // go back to the last 100 of the height.
                let new_range = self.range((Included(min_height), Included(max_height)));

                // get the number nearest to our height
                match new_range.max() {
                    // nothing was found. Continue the loop, and go the the next previous 100
                    None => {}
                    Some((_, net_upgrade)) => {
                        return *net_upgrade;
                    }
                }
            }
        }
    }

    fn get_version_num_from_height(&self, height: &BlockHeight) -> NetUpgradeVersion {
        if let Some(cfg) = self.get_net_config(height) {
            cfg.get_version_num()
        } else {
            NetUpgradeVersionType::Genesis.get_version_num()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::config::ChainType;
    use crate::chain::{NetUpgradeConfig, NetUpgradeVersionType, NetUpgrades, NetUpgradesExt};
    use crate::primitives::height::Saturating;
    use crate::primitives::BlockHeight;

    #[test]
    fn check_net_upgrade() {
        let mut upgrades = NetUpgrades::new();
        let pos_height = BlockHeight::new(350);
        let dsa_height = BlockHeight::new(3000);

        upgrades.insert(
            BlockHeight::zero(),
            NetUpgradeConfig::create(NetUpgradeVersionType::Genesis, ChainType::Mainnet),
        );

        upgrades.insert(
            BlockHeight::one(),
            NetUpgradeConfig::create(NetUpgradeVersionType::POW, ChainType::Mainnet),
        );

        upgrades.insert(
            pos_height,
            NetUpgradeConfig::create(NetUpgradeVersionType::POS, ChainType::Mainnet),
        );

        upgrades.insert(
            dsa_height,
            NetUpgradeConfig::create(NetUpgradeVersionType::DSA, ChainType::Mainnet),
        );

        // check genesis
        {
            let zero_height = BlockHeight::zero();
            assert!(&upgrades.is_upgrade_activated(&zero_height));
            assert_eq!(&0, &upgrades.get_version_num_from_height(&zero_height));
            assert!(&upgrades.get_net_config(&zero_height).is_none());
        }

        // checking POW
        {
            let one_cfg =
                height_has_upgrade(NetUpgradeVersionType::POW, &BlockHeight::one(), &upgrades);

            // at Block 50, there's no upgrade.
            // The net config should be the same as Block 1.
            height_no_upgrade(&BlockHeight::new(50), &upgrades, &one_cfg);

            // at Block 349, there's no upgrade.
            // The net config should be the same as Block 1 and Block 50.
            height_no_upgrade(&pos_height.saturating_sub(1), &upgrades, &one_cfg);
        }

        // checking POS
        {
            let pos_cfg = height_has_upgrade(NetUpgradeVersionType::POS, &pos_height, &upgrades);

            // at Block 351, there's no upgrade.
            // The net config should be the same as Block 350.
            height_no_upgrade(&pos_height.saturating_add(1), &upgrades, &pos_cfg);

            height_no_upgrade(&pos_height.saturating_add(125), &upgrades, &pos_cfg);

            height_no_upgrade(&dsa_height.saturating_sub(1), &upgrades, &pos_cfg)
        }

        // checking DSA
        {
            let dsa_cfg = height_has_upgrade(NetUpgradeVersionType::DSA, &dsa_height, &upgrades);

            // at Block 3001, there's no upgrade.
            // The net config should be the same as Block 3000.
            height_no_upgrade(&dsa_height.saturating_add(1), &upgrades, &dsa_cfg);

            height_no_upgrade(&dsa_height.saturating_add(1001), &upgrades, &dsa_cfg);

            height_no_upgrade(&dsa_height.saturating_add(3210), &upgrades, &dsa_cfg);
        }
    }

    fn height_has_upgrade(
        vers_type: NetUpgradeVersionType,
        height: &BlockHeight,
        upgrades: &NetUpgrades,
    ) -> NetUpgradeConfig {
        assert!(&upgrades.is_upgrade_activated(height));
        assert_eq!(
            &vers_type.get_version_num(),
            &upgrades.get_version_num_from_height(height)
        );
        let cfg = upgrades.get_net_config(height).expect("should return NetUpgradeConfig");
        assert_eq!(vers_type, cfg.get_version_type());

        cfg
    }

    fn height_no_upgrade(
        height: &BlockHeight,
        upgrades: &NetUpgrades,
        expected_cfg: &NetUpgradeConfig,
    ) {
        assert!(!&upgrades.is_upgrade_activated(&height));
        let cfg = upgrades.get_net_config(&height).expect("should return a NetUpgradeConfig");
        assert_eq!(expected_cfg.get_version_type(), cfg.get_version_type());
        assert_eq!(expected_cfg, &cfg);

        // cannot get a config just by using the BTreeMaps's method.
        assert!(upgrades.get(&height).is_none());
    }
}
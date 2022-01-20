use std::fmt::Error;
use common::chain::config::ChainType;
use common::Uint256;
use crate::chain::config::ChainType;
use crate::chain::upgrades::{NetUpgradeError, UpgradeVersion};
use crate::temp_netupgrade::UpgradeVersion;
use crate::uint::Uint256;

/// Chain Parameters for Proof of Work, as found in
/// https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct POWConfig {
    pub(crate) no_retargeting: bool,
    pub(crate) allow_min_difficulty_blocks: bool,
    pub(crate) limit: Uint256,
}

impl TryFrom<(UpgradeVersion, ChainType)> for POWConfig {
    type Error = Error;

    fn try_from(value: (UpgradeVersion, ChainType)) -> Result<Self, Self::Error> {
       Ok(POWConfig::from(value.1))
    }
}

impl From<ChainType> for POWConfig {
    fn from(chain_type: ChainType) -> Self {
        Self {
            no_retargeting: true,
            allow_min_difficulty_blocks: true,
            limit: limit(&chain_type),
        }
    }
}


fn limit(chain_type: &ChainType) -> Uint256 {
    match chain_type {
        ChainType::Mainnet => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
        ])
    }
}
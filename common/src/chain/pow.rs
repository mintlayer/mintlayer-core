use crate::chain::config::ChainType;
use crate::chain::ChainConfig;
use crate::Uint256;
use std::time::Duration;

/// Chain Parameters for Proof of Work, as found in
/// https://github.com/bitcoin/bitcoin/blob/eca694a4e78d54ce4e29b388b3e81b06e55c2293/src/chainparams.cpp
pub struct PoWChainConfig {
    no_retargeting: bool,
    allow_min_difficulty_blocks: bool,
    limit: Uint256,
}

impl ChainConfig {
    pub fn get_pow_config(&self) -> PoWChainConfig {
        PoWChainConfig {
            no_retargeting: no_retargeting(&self.chain_type()),
            allow_min_difficulty_blocks: allow_min_difficulty_blocks(&self.chain_type()),
            limit: limit(&self.chain_type()),
        }
    }
}

impl PoWChainConfig {
    pub fn no_retargeting(&self) -> bool {
        self.no_retargeting
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        self.allow_min_difficulty_blocks
    }

    pub fn limit(&self) -> Uint256 {
        self.limit
    }

    pub fn target_timespan(&self) -> Duration {
        Duration::new(14 * 24 * 60 * 60, 0)
    }

    pub fn target_spacing(&self) -> Duration {
        Duration::new(10 * 60, 0)
    }

    /// https://github.com/bitcoin/bitcoin/blob/eca694a4e78d54ce4e29b388b3e81b06e55c2293/src/pow.cpp#L56
    pub fn max_difficulty_adjustment_per_interval(&self) -> u64 {
        4
    }
}

fn no_retargeting(chain_type: &ChainType) -> bool {
    match chain_type {
        ChainType::Mainnet | ChainType::Testnet | ChainType::Signet => false,
        ChainType::Regtest => true,
    }
}

fn allow_min_difficulty_blocks(chain_type: &ChainType) -> bool {
    match chain_type {
        ChainType::Mainnet | ChainType::Signet => false,
        ChainType::Testnet | ChainType::Regtest => true,
    }
}

fn limit(chain_type: &ChainType) -> Uint256 {
    match chain_type {
        ChainType::Mainnet | ChainType::Testnet => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
        ]),
        ChainType::Signet => Uint256([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x00000377AE000000,
        ]),
        ChainType::Regtest => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ]),
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::config::create_mainnet;
    use crate::chain::pow::{allow_min_difficulty_blocks, limit, no_retargeting};

    #[test]
    fn check_mainnet_powconfig() {
        let cfg = create_mainnet();

        let mainnet_cfg = cfg.get_pow_config();

        assert_eq!(
            mainnet_cfg.no_retargeting,
            no_retargeting(&cfg.chain_type())
        );
        assert_eq!(
            mainnet_cfg.allow_min_difficulty_blocks,
            allow_min_difficulty_blocks(&cfg.chain_type())
        );
        assert_eq!(mainnet_cfg.limit, limit(&cfg.chain_type()));

        assert_eq!(mainnet_cfg.no_retargeting, false);
        assert_eq!(mainnet_cfg.allow_min_difficulty_blocks, false);
    }
}

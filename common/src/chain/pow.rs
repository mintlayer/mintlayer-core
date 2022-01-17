use crate::chain::config::ChainType;
use crate::uint::Uint256;

/// Chain Parameters for Proof of Work, as found in
/// https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct POWConfig {
    pub(crate) no_retargeting: bool,
    pub(crate) allow_min_difficulty_blocks: bool,
    pub(crate) limit: Uint256,
}

impl From<ChainType> for POWConfig {
    fn from(chain_type: ChainType) -> Self {
        Self {
            no_retargeting: no_retargeting(&chain_type),
            allow_min_difficulty_blocks: allow_min_difficulty_blocks(&chain_type),
            limit: limit(&chain_type),
        }
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
    use super::*;

    #[test]
    fn check_pow_limit() {
        let regtest = ChainType::Regtest;
        let str_format = format!("{:?}", limit(&regtest));
        assert_eq!(
            "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            &str_format,
        );

        let mainnet = ChainType::Mainnet;
        let str_format = format!("{:?}", limit(&mainnet));
        assert_eq!(
            "0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            &str_format,
        );

        let signet = ChainType::Signet;
        let str_format = format!("{:?}", limit(&signet));
        assert_eq!(
            "0x00000377ae000000000000000000000000000000000000000000000000000000",
            &str_format,
        );
    }

    #[test]
    fn check_from_chain_type() {
        let cfg = POWConfig::from(ChainType::Mainnet);
        assert!(!cfg.no_retargeting);
        assert!(!cfg.allow_min_difficulty_blocks);

        let cfg = POWConfig::from(ChainType::Regtest);
        assert!(cfg.no_retargeting);
        assert!(cfg.allow_min_difficulty_blocks);

        let cfg = POWConfig::from(ChainType::Testnet);
        assert!(!cfg.no_retargeting);
        assert!(cfg.allow_min_difficulty_blocks);
    }
}

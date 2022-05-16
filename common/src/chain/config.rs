use crate::address::Address;
use crate::chain::block::Block;
use crate::chain::block::ConsensusData;
use crate::chain::transaction::Transaction;
use crate::chain::upgrades::NetUpgrades;
use crate::chain::{PoWChainConfig, UpgradeVersion};
use crate::primitives::id::{Id, H256};
use crate::primitives::BlockDistance;
use crate::primitives::{version::SemVer, BlockHeight};
use std::collections::BTreeMap;

type HashType = Id<Block>;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    strum::Display,
    strum::EnumVariantNames,
    strum::EnumString,
)]
pub enum ChainType {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    #[allow(dead_code)]
    chain_type: ChainType,
    address_prefix: String,
    #[allow(dead_code)]
    rpc_port: u16,
    #[allow(dead_code)]
    p2p_port: u16,
    #[allow(dead_code)]
    height_checkpoint_data: BTreeMap<BlockHeight, HashType>,
    #[allow(dead_code)]
    net_upgrades: NetUpgrades<UpgradeVersion>,
    #[allow(dead_code)]
    magic_bytes: [u8; 4],
    #[allow(dead_code)]
    genesis_block: Block,
    #[allow(dead_code)]
    blockreward_maturity: BlockDistance,
    #[allow(dead_code)]
    version: SemVer,
}

impl ChainConfig {
    pub fn address_prefix(&self) -> &str {
        &self.address_prefix
    }

    pub fn genesis_block(&self) -> &Block {
        &self.genesis_block
    }

    pub fn magic_bytes(&self) -> &[u8; 4] {
        &self.magic_bytes
    }

    pub fn magic_bytes_as_u32(&self) -> u32 {
        u32::from_le_bytes(*self.magic_bytes())
    }

    pub fn version(&self) -> &SemVer {
        &self.version
    }

    pub fn chain_type(&self) -> &ChainType {
        &self.chain_type
    }

    pub fn net_upgrade(&self) -> &NetUpgrades<UpgradeVersion> {
        &self.net_upgrades
    }

    pub const fn get_proof_of_work_config(&self) -> PoWChainConfig {
        PoWChainConfig::new(self.chain_type)
    }

    pub const fn get_blockreward_maturity(&self) -> &BlockDistance {
        &self.blockreward_maturity
    }
}

const MAINNET_ADDRESS_PREFIX: &str = "mlt";
// If block time is 2 minutes (which is my goal eventually), then 500 is equivalent to 100 in bitcoin's 10 minutes.
const MAINNET_BLOCKREWARD_MATURITY: BlockDistance = BlockDistance::new(500);
// DSA allows us to have blocks up to 1mb
pub const MAX_BLOCK_WEIGHT: usize = 1_048_576;

fn create_mainnet_genesis() -> Block {
    use crate::chain::transaction::{Destination, TxInput, TxOutput};
    use crate::primitives::Amount;

    let genesis_message = b"".to_vec();
    let genesis_mint_receiver = Address::new_with_hrp(MAINNET_ADDRESS_PREFIX, [])
        .expect("Failed to create genesis mint address");
    let input = TxInput::new(
        Id::<Transaction>::new(&H256::zero()).into(),
        0,
        genesis_message,
    );
    let output = TxOutput::new(
        Amount::from_atoms(100000000000000),
        Destination::Address(genesis_mint_receiver),
    );
    let tx = Transaction::new(0, vec![input], vec![output], 0)
        .expect("Failed to create genesis coinbase transaction");

    Block::new(vec![tx], None, 1639975460, ConsensusData::None)
        .expect("Error creating genesis block")
}

#[allow(dead_code)]
pub fn create_mainnet() -> ChainConfig {
    ChainConfig {
        chain_type: ChainType::Mainnet,
        address_prefix: MAINNET_ADDRESS_PREFIX.to_owned(),
        height_checkpoint_data: BTreeMap::<BlockHeight, HashType>::new(),
        net_upgrades: Default::default(),
        rpc_port: 15234,
        p2p_port: 8978,
        magic_bytes: [0x1a, 0x64, 0xe5, 0xf1],
        genesis_block: create_mainnet_genesis(),
        version: SemVer::new(0, 1, 0),
        blockreward_maturity: MAINNET_BLOCKREWARD_MATURITY,
    }
}

// TODO: use builder type?
#[allow(clippy::too_many_arguments)]
#[cfg(features = "testing")]
pub fn create_custom(
    chain_type: Option<ChainType>,
    address_prefix: Option<String>,
    rpc_port: Option<u16>,
    p2p_port: Option<u16>,
    height_checkpoint_data: Option<BTreeMap<BlockHeight, HashType>>,
    net_upgrades: Option<NetUpgrades<UpgradeVersion>>,
    magic_bytes: Option<[u8; 4]>,
    genesis_block: Option<Block>,
    version: Option<SemVer>,
    blockreward_maturity: Option<BlockDistance>,
) -> ChainConfig {
    ChainConfig {
        chain_type: chain_type.unwrap_or(ChainType::Mainnet),
        address_prefix: address_prefix.unwrap_or_else(|| MAINNET_ADDRESS_PREFIX.to_owned()),
        height_checkpoint_data: height_checkpoint_data.unwrap_or_default(),
        net_upgrades: net_upgrades.unwrap_or_default(),
        rpc_port: rpc_port.unwrap_or(15234),
        p2p_port: p2p_port.unwrap_or(8978),
        magic_bytes: magic_bytes.unwrap_or([0x1a, 0x64, 0xe5, 0xf1]),
        genesis_block: genesis_block.unwrap_or_else(create_mainnet_genesis),
        version: version.unwrap_or_else(|| SemVer::new(0, 1, 0)),
        blockreward_maturity: blockreward_maturity.unwrap_or(MAINNET_BLOCKREWARD_MATURITY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_creation() {
        let config = create_mainnet();

        assert!(!config.net_upgrades.is_empty());
        assert_eq!(1, config.net_upgrades.len());
        assert_eq!(config.chain_type(), &ChainType::Mainnet);
    }

    #[test]
    #[cfg(feature = "testing")]
    fn custom_creation() {
        let config = create_custom(
            Some(ChainType::Regtest),
            None,
            None,
            None,
            None,
            None,
            Some([0x11, 0x22, 0x33, 0x44]),
            None,
            Some(SemVer::new(1, 2, 3)),
            None,
        );
        let mainnet = create_mainnet();
        assert_eq!(config.address_prefix(), mainnet.address_prefix(),);
        assert_eq!(config.genesis_block(), mainnet.genesis_block(),);
        assert_ne!(config.magic_bytes(), mainnet.magic_bytes(),);
        assert_ne!(config.version(), mainnet.version(),);
    }
}

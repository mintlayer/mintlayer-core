use crypto::key::KeyKind;
use crypto::key::PrivateKey;

use crate::address::pubkeyhash::PublicKeyHash;
use crate::chain::block::Block;
use crate::chain::block::ConsensusData;
use crate::chain::signature::inputsig::InputWitness;
use crate::chain::transaction::Transaction;
use crate::chain::upgrades::NetUpgrades;
use crate::chain::{PoWChainConfig, UpgradeVersion};
use crate::primitives::id::{Id, H256};
use crate::primitives::BlockDistance;
use crate::primitives::{version::SemVer, BlockHeight};
use std::collections::BTreeMap;

#[derive(Debug, Copy, Clone)]
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
    height_checkpoint_data: BTreeMap<BlockHeight, Id<Block>>,
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

    pub fn version(&self) -> &SemVer {
        &self.version
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

const MAINNET_ADDRESS_PREFIX: &str = "mtc";
#[allow(dead_code)]
const TESTNET_ADDRESS_PREFIX: &str = "tmt";

// If block time is 2 minutes (which is my goal eventually), then 500 is equivalent to 100 in bitcoin's 10 minutes.
const MAINNET_BLOCKREWARD_MATURITY: BlockDistance = BlockDistance::new(500);
// DSA allows us to have blocks up to 1mb
pub const MAX_BLOCK_WEIGHT: usize = 1_048_576;

fn create_mainnet_genesis() -> Block {
    use crate::chain::transaction::{Destination, TxInput, TxOutput};
    use crate::primitives::Amount;

    // TODO: replace this with our mint key
    let (_mint_priv_key, mint_pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let genesis_mint_receiver_pubkeyhash = PublicKeyHash::from(&mint_pub_key);

    let genesis_message = b"".to_vec();
    let input = TxInput::new(
        Id::<Transaction>::new(&H256::zero()).into(),
        0,
        InputWitness::NoSignature(Some(genesis_message)),
    );
    // TODO: replace this with the real genesis mint value
    let output = TxOutput::new(
        Amount::from_atoms(100000000000000),
        Destination::Address(genesis_mint_receiver_pubkeyhash),
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
        height_checkpoint_data: BTreeMap::new(),
        net_upgrades: Default::default(),
        rpc_port: 15234,
        p2p_port: 8978,
        magic_bytes: [0x1a, 0x64, 0xe5, 0xf1],
        genesis_block: create_mainnet_genesis(),
        version: SemVer::new(0, 1, 0),
        blockreward_maturity: MAINNET_BLOCKREWARD_MATURITY,
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[allow(clippy::eq_op)]
    fn mainnet_creation() {
        use super::*;
        let config = create_mainnet();

        assert!(!config.net_upgrades.is_empty());
        assert_eq!(1, config.net_upgrades.len());
    }
}

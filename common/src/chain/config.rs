use crate::address::Address;
use crate::chain::block::Block;
use crate::chain::transaction::Transaction;
use crate::chain::upgrades::NetUpgrades;
use crate::chain::{PoWChainConfig, UpgradeVersion};
use crate::primitives::consensus_data::ConsensusData;
use crate::primitives::id::{Id, H256};
use crate::primitives::{version::SemVer, BlockHeight};
use std::collections::BTreeMap;

type HashType = Id<Block>;

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
    height_checkpoint_data: BTreeMap<BlockHeight, HashType>,
    #[allow(dead_code)]
    net_upgrades: NetUpgrades<UpgradeVersion>,
    #[allow(dead_code)]
    magic_bytes: [u8; 4],
    #[allow(dead_code)]
    genesis_block: Block,
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
}

const MAINNET_ADDRESS_PREFIX: &str = "mlt";

fn create_mainnet_genesis() -> Block {
    use crate::chain::transaction::{Destination, TxInput, TxOutput};
    use crate::primitives::Amount;

    let genesis_message = b"".to_vec();
    let genesis_mint_receiver = Address::new_with_hrp(MAINNET_ADDRESS_PREFIX, [])
        .expect("Failed to create genesis mint address");
    let input = TxInput::new(Id::new(&H256::zero()), 0, genesis_message);
    let output = TxOutput::new(
        Amount::new(100000000000000),
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

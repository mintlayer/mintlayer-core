use crate::primitives::{AddressExtNoData, BlockHeight};
use std::collections::BTreeMap;

type HashType = Vec<u8>; // temp type until crypto is ready

#[derive(Debug, Copy, Clone)]
pub enum ChainType {
    Mainnet,
    // Testnet,
    // Regtest,
    // Signet,
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    chain_type: ChainType,
    address_prefix: String,
    rpc_port: u16,
    p2p_port: u16,
    height_checkpoint_data: BTreeMap<BlockHeight, HashType>,
    magic_bytes: [u8; 4],
}

impl AddressExtNoData for ChainConfig {
    fn hrp(&self) -> &str {
        &self.address_prefix
    }
}

#[allow(dead_code)]
pub fn create_mainnet() -> ChainConfig {
    ChainConfig {
        chain_type: ChainType::Mainnet,
        address_prefix: "mlt".to_owned(),
        height_checkpoint_data: BTreeMap::<BlockHeight, HashType>::new(),
        rpc_port: 15234,
        p2p_port: 8978,
        magic_bytes: [0x1a, 0x64, 0xe5, 0xf1],
    }
}

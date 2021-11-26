use crate::chain::transaction::Transaction;
use crypto::hash::Hash256;

#[derive(Debug, Clone, PartialEq)]
pub struct BlockHeader {
    pub version: i32,
    pub hash_prev_block: Hash256,
    pub hash_merkle_root: Hash256,
    pub time: u32,
    pub consensus_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

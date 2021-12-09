use crate::chain::transaction::Transaction;
use crate::primitives::H256;
use crate::primitives::Idable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub hash_prev_block: H256,
    pub hash_merkle_root: H256,
    pub time: u32,
    pub consensus_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Idable for Block {
    fn get_id(&self) -> H256 {
        H256::from_low_u64_ne(self.header.time as u64) // TODO
    }
}

impl Block {
    pub fn get_prev_block_id(&self) -> H256 {
        self.header.hash_prev_block
    }
}

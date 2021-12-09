use crate::chain::transaction::Transaction;
use crate::primitives::H256;
use crate::primitives::Idable;

pub type ConsensusData = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub hash_prev_block: H256,
    pub hash_merkle_root: H256,
    pub time: u32,
    pub consensus_data: ConsensusData, // this is nBits and nNonce(should be more than 32 uint)
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

    pub fn calculate_hash(&self) ->  H256 {
        todo!()
    }
}

use core::panic;

use crate::chain::transaction::Transaction;
use crate::primitives::merkle;
use crate::primitives::Idable;
use crate::primitives::H256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub hash_prev_block: H256,
    pub hash_merkle_root: H256,
    pub time: u32,
    pub consensus_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockV1 {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    V1(BlockV1),
}

impl BlockV1 {
    pub fn get_merkle_root(&self) -> Result<H256, merkle::MerkleTreeFormError> {
        if self.transactions.is_empty() {
            panic!("Cannot calculate merkleroot of an empty block");
        }
        if self.transactions.len() == 1 {
            // using bitcoin's way, blocks that only have the coinbase use their coinbase as the merkleroot
            return Ok(self.transactions[0].get_id());
        }
        let hashes: Vec<H256> = self.transactions.iter().map(|tx| tx.get_id()).collect();
        let t = merkle::merkletree_from_vec(&hashes)?;
        Ok(t.root())
    }
}

impl Block {
    pub fn get_prev_block_id(&self) -> H256 {
        match &self {
            Block::V1(blk) => blk.header.hash_prev_block,
        }
    }

    pub fn get_merkle_root(&self) -> Result<H256, merkle::MerkleTreeFormError> {
        match &self {
            Block::V1(blk) => blk.get_merkle_root(),
        }
    }
}

impl Idable for Block {
    fn get_id(&self) -> H256 {
        match &self {
            Block::V1(blk) => H256::from_low_u64_ne(blk.header.time as u64), // TODO
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::transaction::TransactionV1;

    use super::*;
    use rand::Rng;

    #[test]
    #[should_panic(expected = "Cannot calculate merkleroot of an empty block")]
    fn empty_block_merkleroot() {
        let mut rng = rand::thread_rng();

        let header = BlockHeader {
            consensus_data: Vec::new(),
            hash_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: H256::zero(),
            time: rng.gen(),
            version: 1,
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });
        let _res = block.get_merkle_root();
    }

    #[test]
    fn block_merkleroot_only_coinbase() {
        let mut rng = rand::thread_rng();

        let header = BlockHeader {
            consensus_data: Vec::new(),
            hash_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: H256::zero(),
            time: rng.gen(),
            version: 1,
        };

        let coinbase = Transaction::V1(TransactionV1 {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        });

        let block = Block::V1(BlockV1 {
            header,
            transactions: vec![coinbase.clone()],
        });
        let res = block.get_merkle_root().unwrap();
        assert_eq!(res, coinbase.get_id());
    }
}

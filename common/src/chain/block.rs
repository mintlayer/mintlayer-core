// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

use crate::chain::transaction::Transaction;
use crate::primitives::merkle;
use crate::primitives::Id;
use crate::primitives::Idable;
use crate::primitives::H256;

// TODO: make block and header fields private with appropriate getters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderV1 {
    pub hash_prev_block: H256,
    pub tx_merkle_root: H256,
    pub witness_merkle_root: H256,
    pub time: u32,
    pub consensus_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockV1 {
    pub header: BlockHeaderV1,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    V1(BlockV1),
}

impl BlockV1 {
    pub fn get_merkle_root(&self) -> Result<H256, merkle::MerkleTreeFormError> {
        if self.transactions.len() == 1 {
            // using bitcoin's way, blocks that only have the coinbase use their coinbase as the merkleroot
            return Ok(self.transactions[0].get_id().get());
        }
        let hashes: Vec<H256> = self.transactions.iter().map(|tx| tx.get_id().get()).collect();
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

impl Idable<Block> for Block {
    fn get_id(&self) -> Id<Self> {
        match &self {
            Block::V1(blk) => Id::new(&H256::from_low_u64_ne(blk.header.time as u64)), // TODO
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{chain::transaction::TransactionV1, primitives::merkle::MerkleTreeFormError};

    use super::*;
    use rand::Rng;

    #[test]
    fn empty_block_merkleroot() {
        let mut rng = rand::thread_rng();

        let header = BlockHeaderV1 {
            consensus_data: Vec::new(),
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: H256::zero(),
            time: rng.gen(),
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });
        let _res = block.get_merkle_root();
        assert_eq!(_res.unwrap_err(), MerkleTreeFormError::TooSmall(0));
    }

    #[test]
    fn block_merkleroot_only_coinbase() {
        let mut rng = rand::thread_rng();

        let header = BlockHeaderV1 {
            consensus_data: Vec::new(),
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: H256::zero(),
            time: rng.gen(),
        };

        let coinbase = Transaction::V1(TransactionV1 {
            flags: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        });

        let block = Block::V1(BlockV1 {
            header,
            transactions: vec![coinbase.clone()],
        });
        let res = block.get_merkle_root().unwrap();
        assert_eq!(res, coinbase.get_id().get());
    }
}

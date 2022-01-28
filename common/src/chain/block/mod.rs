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
use crate::primitives::merkle::MerkleTreeFormError;
use crate::primitives::Id;
use crate::primitives::Idable;
use crate::primitives::H256;
mod block_v1;
mod data;

use block_v1::BlockHeader;
use block_v1::BlockV1;
pub use data::*;
use parity_scale_codec::{Decode, Encode};

pub use block_v1::ConsensusData;

pub fn calculate_tx_merkle_root(
    transactions: &[Transaction],
) -> Result<H256, merkle::MerkleTreeFormError> {
    if transactions.len() == 1 {
        // using bitcoin's way, blocks that only have the coinbase use their coinbase as the merkleroot
        return Ok(transactions[0].get_id().get());
    }
    let hashes: Vec<H256> = transactions.iter().map(|tx| tx.get_id().get()).collect();
    let t = merkle::merkletree_from_vec(&hashes)?;
    Ok(t.root())
}

pub fn calculate_witness_merkle_root(
    transactions: &[Transaction],
) -> Result<H256, merkle::MerkleTreeFormError> {
    // TODO: provide implementation based on real serialization instead of get_id()
    if transactions.len() == 1 {
        // using bitcoin's way, blocks that only have the coinbase use their coinbase as the merkleroot
        return Ok(transactions[0].get_id().get());
    }
    let hashes: Vec<H256> = transactions.iter().map(|tx| tx.get_id().get()).collect();
    let t = merkle::merkletree_from_vec(&hashes)?;
    Ok(t.root())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockCreationError {
    MerkleTreeError(MerkleTreeFormError),
}

impl From<MerkleTreeFormError> for BlockCreationError {
    fn from(e: MerkleTreeFormError) -> Self {
        BlockCreationError::MerkleTreeError(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Block {
    #[codec(index = 1)]
    V1(BlockV1),
}

impl From<Id<BlockV1>> for Id<Block> {
    fn from(id_block_v1: Id<BlockV1>) -> Self {
        Id::new(&id_block_v1.get())
    }
}

impl From<Id<Block>> for Id<BlockV1> {
    fn from(id_block: Id<Block>) -> Id<BlockV1> {
        Id::new(&id_block.get())
    }
}

impl Block {
    pub fn new(
        transactions: Vec<Transaction>,
        hash_prev_block: Id<Block>,
        time: u32,
        consensus_data: Vec<u8>,
    ) -> Result<Self, BlockCreationError> {
        let tx_merkle_root = calculate_tx_merkle_root(&transactions)?;
        let witness_merkle_root = calculate_witness_merkle_root(&transactions)?;

        let header = BlockHeader {
            time,
            consensus_data,
            hash_prev_block: hash_prev_block.into(),
            tx_merkle_root,
            witness_merkle_root,
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions,
        });

        Ok(block)
    }

    pub fn update_consensus_data(&mut self, consensus_data: Vec<u8>) {
        match self {
            Block::V1(blk) => blk.update_consensus_data(consensus_data),
        }
    }

    pub fn get_merkle_root(&self) -> H256 {
        match &self {
            Block::V1(blk) => blk.get_tx_merkle_root(),
        }
    }

    pub fn get_witness_merkle_root(&self) -> H256 {
        match &self {
            Block::V1(blk) => blk.get_witness_merkle_root(),
        }
    }

    pub fn get_header(&self) -> &BlockHeader {
        match &self {
            Block::V1(blk) => blk.get_header(),
        }
    }

    pub fn get_block_time(&self) -> u32 {
        match &self {
            Block::V1(blk) => blk.get_block_time(),
        }
    }

    pub fn get_transactions(&self) -> &Vec<Transaction> {
        match &self {
            Block::V1(blk) => blk.get_transactions(),
        }
    }

    pub fn get_prev_block_id(&self) -> Id<Block> {
        match &self {
            Block::V1(blk) => blk.get_prev_block_id().clone().into(),
        }
    }
}

impl Idable<Block> for Block {
    fn get_id(&self) -> Id<Self> {
        match &self {
            Block::V1(blk) => Id::new(&H256::from_low_u64_ne(blk.get_block_time() as u64)), // TODO
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{chain::transaction::Transaction, primitives::merkle::MerkleTreeFormError};

    use super::*;
    use rand::Rng;

    #[test]
    fn empty_block_merkleroot() {
        let mut rng = rand::thread_rng();

        let header = BlockHeader {
            consensus_data: Vec::new(),
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: Id::new(&H256::zero()),
            time: rng.gen(),
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });
        let _res = calculate_tx_merkle_root(block.get_transactions());
        assert_eq!(_res.unwrap_err(), MerkleTreeFormError::TooSmall(0));
    }

    #[test]
    fn block_merkleroot_only_coinbase() {
        let mut rng = rand::thread_rng();

        let header = BlockHeader {
            consensus_data: Vec::new(),
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: Id::new(&H256::zero()),
            time: rng.gen(),
        };

        let coinbase = Transaction::new(0, Vec::new(), Vec::new(), 0).unwrap();

        let block = Block::V1(BlockV1 {
            header,
            transactions: vec![coinbase.clone()],
        });
        let res = calculate_tx_merkle_root(block.get_transactions()).unwrap();
        assert_eq!(res, coinbase.get_id().get());
    }
}

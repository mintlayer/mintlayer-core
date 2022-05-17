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
use crate::primitives::{Id, Idable, H256};
pub mod block_index;
pub use block_index::*;
mod block_v1;
pub mod consensus_data;

pub use block_v1::BlockHeader;
use block_v1::BlockV1;
pub use consensus_data::ConsensusData;
use serialization::{Decode, Encode};

use super::ChainConfig;

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlockConsistencyError {
    #[error("Block version in serialization doesn't match header `{0}` != `{1}`")]
    VersionMismatch(u32, u32),
}

pub fn calculate_tx_merkle_root(
    transactions: &[Transaction],
) -> Result<Option<H256>, merkle::MerkleTreeFormError> {
    if transactions.is_empty() {
        return Ok(None);
    }
    if transactions.len() == 1 {
        // using bitcoin's way, blocks that only have the coinbase use their coinbase as the merkleroot
        return Ok(Some(transactions[0].get_id().get()));
    }
    let hashes: Vec<H256> = transactions.iter().map(|tx| tx.get_id().get()).collect();
    let t = merkle::merkletree_from_vec(&hashes)?;
    Ok(Some(t.root()))
}

pub fn calculate_witness_merkle_root(
    transactions: &[Transaction],
) -> Result<Option<H256>, merkle::MerkleTreeFormError> {
    if transactions.is_empty() {
        return Ok(None);
    }
    // TODO: provide implementation based on real serialization instead of get_id()
    if transactions.len() == 1 {
        // using bitcoin's way, blocks that only have the coinbase use their coinbase as the merkleroot
        return Ok(Some(transactions[0].get_id().get()));
    }
    let hashes: Vec<H256> = transactions.iter().map(|tx| tx.get_id().get()).collect();
    let t = merkle::merkletree_from_vec(&hashes)?;
    Ok(Some(t.root()))
}

trait BlockVersion {
    const BLOCK_VERSION: u32;
    // self is not required in implementations, but unfortunately, we need it because rust doesn't have a decltype operator
    fn static_version(&self) -> u32 {
        Self::BLOCK_VERSION
    }
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

impl Block {
    pub fn new(
        transactions: Vec<Transaction>,
        prev_block_hash: Option<Id<Block>>,
        time: u32,
        consensus_data: ConsensusData,
    ) -> Result<Self, BlockCreationError> {
        let tx_merkle_root = calculate_tx_merkle_root(&transactions)?;
        let witness_merkle_root = calculate_witness_merkle_root(&transactions)?;

        type BlockWithVersion = BlockV1;
        let version_value = <BlockWithVersion as BlockVersion>::BLOCK_VERSION;

        let header = BlockHeader {
            block_version: version_value,
            time,
            consensus_data,
            prev_block_hash,
            tx_merkle_root,
            witness_merkle_root,
        };

        let block = Block::V1(BlockWithVersion {
            header,
            transactions,
        });

        Ok(block)
    }

    // this function is needed to avoid a circular dependency with storage
    pub fn new_with_no_consensus(
        transactions: Vec<Transaction>,
        prev_block_hash: Option<Id<Block>>,
        time: u32,
    ) -> Result<Self, BlockCreationError> {
        let tx_merkle_root = calculate_tx_merkle_root(&transactions)?;
        let witness_merkle_root = calculate_witness_merkle_root(&transactions)?;

        type BlockWithVersion = BlockV1;
        let version_value = <BlockWithVersion as BlockVersion>::BLOCK_VERSION;

        let header = BlockHeader {
            block_version: version_value,
            time,
            consensus_data: ConsensusData::None,
            prev_block_hash,
            tx_merkle_root,
            witness_merkle_root,
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions,
        });

        Ok(block)
    }

    pub fn update_consensus_data(&mut self, consensus_data: ConsensusData) {
        match self {
            Block::V1(blk) => blk.update_consensus_data(consensus_data),
        }
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        match self {
            Block::V1(blk) => blk.consensus_data(),
        }
    }

    pub fn static_version(&self) -> u32 {
        match &self {
            Block::V1(blk) => blk.static_version(),
        }
    }

    pub fn check_version(&self) -> Result<(), BlockConsistencyError> {
        match &self {
            Block::V1(blk) => blk.check_version(),
        }
    }

    pub fn version(&self) -> u32 {
        match &self {
            Block::V1(blk) => blk.version(),
        }
    }

    pub fn merkle_root(&self) -> Option<H256> {
        match &self {
            Block::V1(blk) => blk.tx_merkle_root(),
        }
    }

    pub fn witness_merkle_root(&self) -> Option<H256> {
        match &self {
            Block::V1(blk) => blk.witness_merkle_root(),
        }
    }

    pub fn header(&self) -> &BlockHeader {
        match &self {
            Block::V1(blk) => blk.header(),
        }
    }

    pub fn block_time(&self) -> u32 {
        match &self {
            Block::V1(blk) => blk.block_time(),
        }
    }

    pub fn transactions(&self) -> &Vec<Transaction> {
        match &self {
            Block::V1(blk) => blk.transactions(),
        }
    }

    pub fn prev_block_id(&self) -> Option<Id<Block>> {
        match &self {
            Block::V1(blk) => blk.get_prev_block_id().clone(),
        }
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.prev_block_id() == None && chain_config.genesis_block().get_id() == self.get_id()
    }
}

impl Idable for Block {
    type Tag = Block;
    fn get_id(&self) -> Id<Self> {
        // Block ID is just the hash of its header. The transaction list is committed to by the
        // inclusion of transaction Merkle root in the header. We also include the version number.
        self.header().get_id()
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::transaction::Transaction;

    use super::*;
    use crypto::random::{make_pseudo_rng, Rng};

    #[test]
    fn empty_block_merkleroot() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            block_version: 1,
            consensus_data: ConsensusData::None,
            tx_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            witness_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            prev_block_hash: None,
            time: rng.gen(),
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });
        let _res = calculate_tx_merkle_root(block.transactions());
        assert_eq!(_res.unwrap(), None);
    }

    #[test]
    fn block_merkleroot_only_one_transaction() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            block_version: 1,
            consensus_data: ConsensusData::None,
            tx_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            witness_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            prev_block_hash: None,
            time: rng.gen(),
        };

        let one_transaction = Transaction::new(0, Vec::new(), Vec::new(), 0).unwrap();

        let block = Block::V1(BlockV1 {
            header,
            transactions: vec![one_transaction.clone()],
        });
        let res = calculate_tx_merkle_root(block.transactions()).unwrap();
        let res = res.unwrap();
        assert_eq!(res, one_transaction.get_id().get());
    }

    #[test]
    fn version_consistency_error() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            block_version: 666,
            consensus_data: ConsensusData::None,
            tx_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            witness_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            prev_block_hash: None,
            time: rng.gen(),
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });
        assert_eq!(
            block.check_version().unwrap_err(),
            BlockConsistencyError::VersionMismatch(666, 1)
        )
    }

    #[test]
    fn ensure_serialized_version_is_valid() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            block_version: 1,
            consensus_data: ConsensusData::None,
            tx_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            witness_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            prev_block_hash: None,
            time: rng.gen(),
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });

        let encoded_block = block.encode();
        let first_byte = *encoded_block.get(0).unwrap();

        assert_eq!(1, first_byte)
    }
}

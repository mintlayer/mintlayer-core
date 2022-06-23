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
use crate::primitives::{Id, Idable, VersionTag, H256};
pub mod block_index;
pub use block_index::*;
mod block_v1;
pub mod consensus_data;

pub mod block_size;

pub mod timestamp;

pub mod height_skip;

pub use block_v1::BlockHeader;
use block_v1::BlockV1;
pub use consensus_data::ConsensusData;
use serialization::{DirectDecode, DirectEncode};

use self::block_size::BlockSize;
use self::timestamp::BlockTimestamp;

use super::ChainConfig;

pub fn calculate_tx_merkle_root(
    transactions: &[Transaction],
) -> Result<Option<H256>, merkle::MerkleTreeFormError> {
    const TX_HASHER: fn(&Transaction) -> H256 = |tx: &Transaction| tx.get_id().get();
    calculate_generic_merkle_root(&TX_HASHER, transactions)
}

pub fn calculate_witness_merkle_root(
    transactions: &[Transaction],
) -> Result<Option<H256>, merkle::MerkleTreeFormError> {
    const TX_HASHER: fn(&Transaction) -> H256 = |tx: &Transaction| tx.serialized_hash().get();
    calculate_generic_merkle_root(&TX_HASHER, transactions)
}

fn calculate_generic_merkle_root(
    tx_hasher: &fn(&Transaction) -> H256,
    transactions: &[Transaction],
) -> Result<Option<H256>, merkle::MerkleTreeFormError> {
    if transactions.is_empty() {
        return Ok(None);
    }

    if transactions.len() == 1 {
        // using bitcoin's way, blocks that only have the coinbase (or a single tx in general)
        // use their coinbase as the merkleroot
        return Ok(Some(tx_hasher(&transactions[0])));
    }
    let hashes: Vec<H256> = transactions.iter().map(tx_hasher).collect();
    let t = merkle::merkletree_from_vec(&hashes)?;
    Ok(Some(t.root()))
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

#[derive(Debug, Clone, PartialEq, Eq, DirectEncode, DirectDecode)]
pub enum Block {
    V1(BlockV1),
}

impl Block {
    pub fn new(
        transactions: Vec<Transaction>,
        prev_block_hash: Option<Id<Block>>,
        timestamp: BlockTimestamp,
        consensus_data: ConsensusData,
    ) -> Result<Self, BlockCreationError> {
        let tx_merkle_root = calculate_tx_merkle_root(&transactions)?;
        let witness_merkle_root = calculate_witness_merkle_root(&transactions)?;

        let header = BlockHeader {
            version: VersionTag::default(),
            timestamp,
            consensus_data,
            prev_block_id: prev_block_hash,
            tx_merkle_root,
            witness_merkle_root,
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions,
        });

        Ok(block)
    }

    // this function is needed to avoid a circular dependency with storage
    pub fn new_with_no_consensus(
        transactions: Vec<Transaction>,
        prev_block_hash: Option<Id<Block>>,
        timestamp: BlockTimestamp,
    ) -> Result<Self, BlockCreationError> {
        let tx_merkle_root = calculate_tx_merkle_root(&transactions)?;
        let witness_merkle_root = calculate_witness_merkle_root(&transactions)?;

        let header = BlockHeader {
            version: VersionTag::default(),
            timestamp,
            consensus_data: ConsensusData::None,
            prev_block_id: prev_block_hash,
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

    pub fn timestamp(&self) -> BlockTimestamp {
        match &self {
            Block::V1(blk) => blk.timestamp(),
        }
    }

    pub fn transactions(&self) -> &Vec<Transaction> {
        match &self {
            Block::V1(blk) => blk.transactions(),
        }
    }

    pub fn prev_block_id(&self) -> Option<Id<Block>> {
        match &self {
            Block::V1(blk) => blk.prev_block_id().clone(),
        }
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.header().is_genesis(chain_config)
    }

    pub fn block_size(&self) -> BlockSize {
        BlockSize::new_from_block(self)
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
    use crate::chain::{
        signature::inputsig::InputWitness, transaction::Transaction, OutPointSourceId, TxInput,
    };

    use super::*;
    use crypto::random::{make_pseudo_rng, Rng};
    use serialization::Encode;

    fn check_block_tag(block: &Block) {
        let encoded_block = block.encode();
        let first_byte = *encoded_block.get(0).unwrap();
        assert_eq!(1, first_byte);

        let Block::V1(blockv1) = block;

        // Check serialization and ID of BlockV1 and Block are identical
        assert_eq!(encoded_block, blockv1.encode());
        assert_eq!(block.get_id(), blockv1.get_id());
    }

    #[test]
    fn empty_block_merkleroot() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            version: Default::default(),
            consensus_data: ConsensusData::None,
            tx_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            witness_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            prev_block_id: None,
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });
        let _res = calculate_tx_merkle_root(block.transactions());
        assert_eq!(_res.unwrap(), None);

        check_block_tag(&block);
    }

    #[test]
    fn block_merkleroot_only_one_transaction() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            version: Default::default(),
            consensus_data: ConsensusData::None,
            tx_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            witness_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            prev_block_id: None,
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let one_transaction = Transaction::new(0, Vec::new(), Vec::new(), 0).unwrap();

        let block = Block::V1(BlockV1 {
            header,
            transactions: vec![one_transaction.clone()],
        });
        let res = calculate_tx_merkle_root(block.transactions()).unwrap();
        let res = res.unwrap();
        assert_eq!(res, one_transaction.get_id().get());

        check_block_tag(&block);
    }

    #[test]
    fn tx_with_witness_always_different_merkle_witness_root() {
        let inputs = vec![TxInput::new(
            OutPointSourceId::Transaction(H256::random().into()),
            0,
            InputWitness::NoSignature(Some(b"abc".to_vec())),
        )];

        let one_transaction = Transaction::new(0, inputs, Vec::new(), 0).unwrap();

        let merkle_root = calculate_tx_merkle_root(&[one_transaction.clone()]);
        let witness_merkle_root = calculate_witness_merkle_root(&[one_transaction]);

        assert_ne!(merkle_root, witness_merkle_root);
    }

    #[test]
    fn ensure_serialized_version_is_valid() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            version: Default::default(),
            consensus_data: ConsensusData::None,
            tx_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            witness_merkle_root: Some(H256::from_low_u64_be(rng.gen())),
            prev_block_id: None,
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let block = Block::V1(BlockV1 {
            header,
            transactions: Vec::new(),
        });

        check_block_tag(&block);
    }
}

// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub use crate::chain::{
    block::{
        block_header::BlockHeader,
        block_reward::{BlockReward, BlockRewardTransactable},
        consensus_data::ConsensusData,
    },
    GenBlock,
};

pub mod block_header;
pub mod block_size;
pub mod consensus_data;
pub mod timestamp;

mod block_reward;
mod block_v1;

use std::iter;

use serialization::{DirectDecode, DirectEncode};
use typename::TypeName;

use crate::{
    chain::block::{
        block_size::BlockSize,
        block_v1::{BlockBody, BlockV1},
        timestamp::BlockTimestamp,
    },
    primitives::{
        id::{self, WithId},
        merkle::{self, MerkleTreeFormError},
        Id, Idable, VersionTag, H256,
    },
};

use super::signed_transaction::SignedTransaction;

pub fn calculate_tx_merkle_root(body: &BlockBody) -> Result<H256, merkle::MerkleTreeFormError> {
    const TX_HASHER: fn(&SignedTransaction) -> H256 =
        |tx: &SignedTransaction| tx.transaction().get_id().get();
    calculate_generic_merkle_root(&TX_HASHER, body)
}

pub fn calculate_witness_merkle_root(
    body: &BlockBody,
) -> Result<H256, merkle::MerkleTreeFormError> {
    const TX_HASHER: fn(&SignedTransaction) -> H256 =
        |tx: &SignedTransaction| tx.serialized_hash().get();
    calculate_generic_merkle_root(&TX_HASHER, body)
}

fn calculate_generic_merkle_root(
    tx_hasher: &fn(&SignedTransaction) -> H256,
    body: &BlockBody,
) -> Result<H256, merkle::MerkleTreeFormError> {
    let rewards_hash = id::hash_encoded(&body.reward);

    if body.transactions.is_empty() {
        // using bitcoin's way, blocks that only have the coinbase (or a single tx in general)
        // use their coinbase as the merkleroot
        return Ok(rewards_hash);
    }

    let hashes: Vec<H256> = iter::once(rewards_hash)
        .chain(body.transactions.iter().map(tx_hasher))
        .collect();
    let t = merkle::merkletree_from_vec(hashes)?;
    Ok(t.root())
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockCreationError {
    #[error("Merkle tree calculation error: {0}")]
    MerkleTreeError(MerkleTreeFormError),
}

impl From<MerkleTreeFormError> for BlockCreationError {
    fn from(e: MerkleTreeFormError) -> Self {
        BlockCreationError::MerkleTreeError(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, DirectEncode, DirectDecode, TypeName)]
#[must_use]
pub enum Block {
    V1(BlockV1),
}

impl Block {
    pub fn new(
        transactions: Vec<SignedTransaction>,
        prev_block_hash: Id<GenBlock>,
        timestamp: BlockTimestamp,
        consensus_data: ConsensusData,
        reward: BlockReward,
    ) -> Result<Self, BlockCreationError> {
        let body = BlockBody {
            reward,
            transactions,
        };
        let tx_merkle_root = calculate_tx_merkle_root(&body)?;
        let witness_merkle_root = calculate_witness_merkle_root(&body)?;

        let header = BlockHeader {
            version: VersionTag::default(),
            timestamp,
            consensus_data,
            prev_block_id: prev_block_hash,
            tx_merkle_root,
            witness_merkle_root,
        };

        let block = Block::V1(BlockV1 { header, body });

        Ok(block)
    }

    // this function is needed to avoid a circular dependency with storage
    pub fn new_with_no_consensus(
        transactions: Vec<SignedTransaction>,
        prev_block_hash: Id<GenBlock>,
        timestamp: BlockTimestamp,
    ) -> Result<Self, BlockCreationError> {
        let reward = BlockReward::new(Vec::new());
        let body = BlockBody {
            reward,
            transactions,
        };

        let tx_merkle_root = calculate_tx_merkle_root(&body)?;
        let witness_merkle_root = calculate_witness_merkle_root(&body)?;

        let header = BlockHeader {
            version: VersionTag::default(),
            timestamp,
            consensus_data: ConsensusData::None,
            prev_block_id: prev_block_hash,
            tx_merkle_root,
            witness_merkle_root,
        };

        let block = Block::V1(BlockV1 { header, body });

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

    pub fn merkle_root(&self) -> H256 {
        match self {
            Block::V1(blk) => blk.tx_merkle_root(),
        }
    }

    pub fn witness_merkle_root(&self) -> H256 {
        match self {
            Block::V1(blk) => blk.witness_merkle_root(),
        }
    }

    pub fn header(&self) -> &BlockHeader {
        match self {
            Block::V1(blk) => blk.header(),
        }
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        match self {
            Block::V1(blk) => blk.timestamp(),
        }
    }

    pub fn transactions(&self) -> &Vec<SignedTransaction> {
        match self {
            Block::V1(blk) => blk.transactions(),
        }
    }

    pub fn prev_block_id(&self) -> Id<GenBlock> {
        match self {
            Block::V1(blk) => *blk.prev_block_id(),
        }
    }

    pub fn block_size(&self) -> BlockSize {
        BlockSize::new_from_block(self)
    }

    pub fn body(&self) -> &BlockBody {
        match self {
            Block::V1(b) => b.body(),
        }
    }

    /// Returns a reward for this block.
    pub fn block_reward(&self) -> &BlockReward {
        match self {
            Block::V1(b) => b.block_reward(),
        }
    }

    pub fn block_reward_transactable(&self) -> BlockRewardTransactable {
        match self {
            Block::V1(b) => b.block_reward_transactable(),
        }
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

impl PartialEq for WithId<Block> {
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl Eq for WithId<Block> {}

#[cfg(test)]
mod tests {
    use crate::{
        chain::{
            signature::inputsig::InputWitness, tokens::OutputValue, transaction::Transaction,
            Destination, OutPointSourceId, OutputPurpose, TxInput, TxOutput,
        },
        primitives::{id, Amount},
    };

    use super::*;
    use crypto::random::{make_pseudo_rng, Rng};
    use rstest::rstest;
    use serialization::Encode;
    use test_utils::random::Seed;

    fn check_block_tag(block: &Block) {
        let encoded_block = block.encode();
        let first_byte = *encoded_block.first().unwrap();
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
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            prev_block_id: Id::new(H256::from_low_u64_be(rng.gen())),
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let body = BlockBody {
            reward: BlockReward::new(Vec::new()),
            transactions: Vec::new(),
        };

        let block = Block::V1(BlockV1 { header, body });
        calculate_tx_merkle_root(block.body()).unwrap();

        check_block_tag(&block);
    }

    #[test]
    fn block_merkleroot_empty_reward() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            version: Default::default(),
            consensus_data: ConsensusData::None,
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            prev_block_id: Id::new(H256::from_low_u64_be(rng.gen())),
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let body = BlockBody {
            reward: BlockReward::new(Vec::new()),
            transactions: Vec::new(),
        };

        let block = Block::V1(BlockV1 { header, body });
        let res = calculate_tx_merkle_root(block.body()).unwrap();
        assert_eq!(res, id::hash_encoded(block.block_reward()));

        check_block_tag(&block);
    }

    #[test]
    fn block_merkleroot_only_reward() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            version: Default::default(),
            consensus_data: ConsensusData::None,
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            prev_block_id: Id::new(H256::from_low_u64_be(rng.gen())),
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let reward = BlockReward::new(vec![TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        )]);
        let body = BlockBody {
            reward,
            transactions: Vec::new(),
        };

        let block = Block::V1(BlockV1 { header, body });
        let res = calculate_tx_merkle_root(block.body()).unwrap();
        assert_eq!(res, id::hash_encoded(block.block_reward()));

        check_block_tag(&block);
    }

    #[test]
    fn block_merkleroot_only_one_transaction() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            version: Default::default(),
            consensus_data: ConsensusData::None,
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            prev_block_id: Id::new(H256::from_low_u64_be(rng.gen())),
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let one_transaction = SignedTransaction::new(
            Transaction::new(0, Vec::new(), Vec::new(), 0).unwrap(),
            vec![],
        )
        .expect("invalid witness count");
        let body = BlockBody {
            reward: BlockReward::new(Vec::new()),
            transactions: vec![one_transaction],
        };

        let block = Block::V1(BlockV1 { header, body });
        calculate_tx_merkle_root(block.body()).unwrap();

        check_block_tag(&block);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_with_witness_always_different_merkle_witness_root(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let inputs = vec![TxInput::new(
            OutPointSourceId::Transaction(H256::random_using(&mut rng).into()),
            0,
        )];

        let one_transaction = SignedTransaction::new(
            Transaction::new(0, inputs, Vec::new(), 0).unwrap(),
            vec![InputWitness::NoSignature(Some(b"abc".to_vec()))],
        )
        .expect("invalid witness count");
        let body = BlockBody {
            reward: BlockReward::new(Vec::new()),
            transactions: vec![one_transaction],
        };

        let merkle_root = calculate_tx_merkle_root(&body);
        let witness_merkle_root = calculate_witness_merkle_root(&body);

        assert_ne!(merkle_root, witness_merkle_root);
    }

    #[test]
    fn ensure_serialized_version_is_valid() {
        let mut rng = make_pseudo_rng();

        let header = BlockHeader {
            version: Default::default(),
            consensus_data: ConsensusData::None,
            tx_merkle_root: H256::from_low_u64_be(rng.gen()),
            witness_merkle_root: H256::from_low_u64_be(rng.gen()),
            prev_block_id: Id::new(H256::from_low_u64_be(rng.gen())),
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
        };

        let body = BlockBody {
            reward: BlockReward::new(Vec::new()),
            transactions: Vec::new(),
        };

        let block = Block::V1(BlockV1 { header, body });

        check_block_tag(&block);
    }
}

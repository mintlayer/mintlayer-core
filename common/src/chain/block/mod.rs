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

pub mod block_body;
pub mod block_header;
pub mod block_size;
pub mod consensus_data;
pub mod signed_block_header;
pub mod timestamp;

mod block_reward;
mod block_v1;

use serialization::{DirectDecode, DirectEncode};
use typename::TypeName;
use utils::ensure;

use crate::{
    chain::block::{block_size::BlockSize, block_v1::BlockV1, timestamp::BlockTimestamp},
    primitives::{
        id::{HasSubObjWithSameId, WithId},
        Id, Idable, VersionTag, H256,
    },
};

use self::{
    block_body::{BlockBody, BlockMerkleTreeError},
    signed_block_header::SignedBlockHeader,
};

use super::signed_transaction::SignedTransaction;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockCreationError {
    #[error("Merkle tree calculation error: {0}")]
    MerkleTreeError(#[from] BlockMerkleTreeError),
    #[error("Error finding current tip")]
    CurrentTipRetrievalError,
    #[error("Merkle tree mismatch: Provided {0} vs calculated {1}")]
    MerkleTreeMismatch(H256, H256),
    #[error("Witness merkle tree mismatch: Provided {0} vs calculated {1}")]
    WitnessMerkleTreeMismatch(H256, H256),
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

        let merkle_proxy = body.merkle_tree_proxy()?;
        let tx_merkle_root = merkle_proxy.merkle_tree().root();
        let witness_merkle_root = merkle_proxy.witness_merkle_tree().root();

        let header = BlockHeader {
            version: VersionTag::default(),
            timestamp,
            consensus_data,
            prev_block_id: prev_block_hash,
            tx_merkle_root,
            witness_merkle_root,
        };

        let header = header.with_no_signature();

        let block = Block::V1(BlockV1 { header, body });

        Ok(block)
    }

    pub fn new_from_header(
        header: SignedBlockHeader,
        body: BlockBody,
    ) -> Result<Self, BlockCreationError> {
        let merkle_proxy = body.merkle_tree_proxy()?;
        let tx_merkle_root = merkle_proxy.merkle_tree().root();
        let witness_merkle_root = merkle_proxy.witness_merkle_tree().root();

        ensure!(
            header.header().tx_merkle_root == tx_merkle_root,
            BlockCreationError::MerkleTreeMismatch(header.header().tx_merkle_root, tx_merkle_root,)
        );

        ensure!(
            header.header().witness_merkle_root == witness_merkle_root,
            BlockCreationError::WitnessMerkleTreeMismatch(
                header.header().witness_merkle_root,
                witness_merkle_root,
            )
        );

        let block = Block::V1(BlockV1 { header, body });

        Ok(block)
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

    pub fn header(&self) -> &SignedBlockHeader {
        match self {
            Block::V1(blk) => blk.header(),
        }
    }

    pub fn header_mut(&mut self) -> &mut SignedBlockHeader {
        match self {
            Block::V1(blk) => blk.header_mut(),
        }
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        match self {
            Block::V1(blk) => blk.timestamp(),
        }
    }

    pub fn transactions(&self) -> &[SignedTransaction] {
        match self {
            Block::V1(blk) => blk.transactions(),
        }
    }

    pub fn into_transactions(self) -> Vec<SignedTransaction> {
        match self {
            Block::V1(blk) => blk.into_transactions(),
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

    pub fn block_reward_transactable(&self) -> BlockRewardTransactable<'_> {
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
        self.header().header().get_id()
    }
}

impl HasSubObjWithSameId<SignedBlockHeader> for Block {
    fn get_sub_obj(&self) -> &SignedBlockHeader {
        self.header()
    }
}

impl PartialEq for WithId<Block> {
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl serde::Serialize for Id<Block> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.serde_serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Id<Block> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::serde_deserialize(d)
    }
}

impl Eq for WithId<Block> {}

#[cfg(test)]
mod tests {
    use crate::{
        chain::{
            output_value::OutputValue, signature::inputsig::InputWitness, transaction::Transaction,
            Destination, OutPointSourceId, TxInput, TxOutput,
        },
        primitives::{id, Amount},
    };

    use super::*;
    use randomness::{make_pseudo_rng, Rng};
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

        let header = header.with_no_signature();

        let block = Block::V1(BlockV1 { header, body });

        let merkle_proxy = block.body().merkle_tree_proxy().unwrap();
        let merkle_root = merkle_proxy.merkle_tree().root();
        let witness_merkle_root = merkle_proxy.witness_merkle_tree().root();

        // Given that there's only a reward, the merkle root should be the same as the witness merkle root
        assert_eq!(merkle_root, witness_merkle_root);

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

        let header = header.with_no_signature();

        let block = Block::V1(BlockV1 { header, body });

        let merkle_proxy = block.body().merkle_tree_proxy().unwrap();

        let res = merkle_proxy.merkle_tree().root();
        assert_eq!(res, id::hash_encoded(block.block_reward()));

        let merkle_root = merkle_proxy.merkle_tree().root();
        let witness_merkle_root = merkle_proxy.witness_merkle_tree().root();

        // Given that there's only a reward, the merkle root should be the same as the witness merkle root
        assert_eq!(merkle_root, witness_merkle_root);

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

        let reward = BlockReward::new(vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1)),
            Destination::AnyoneCanSpend,
        )]);
        let body = BlockBody {
            reward,
            transactions: Vec::new(),
        };

        let header = header.with_no_signature();

        let block = Block::V1(BlockV1 { header, body });
        let res = block.body().merkle_tree_proxy().unwrap().merkle_tree().root();
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

        let one_transaction =
            SignedTransaction::new(Transaction::new(0, Vec::new(), Vec::new()).unwrap(), vec![])
                .expect("invalid witness count");
        let body = BlockBody {
            reward: BlockReward::new(Vec::new()),
            transactions: vec![one_transaction],
        };

        let header = header.with_no_signature();

        let block = Block::V1(BlockV1 { header, body });

        let merkle_proxy = block.body().merkle_tree_proxy().unwrap();
        let merkle_root = merkle_proxy.merkle_tree().root();
        let witness_merkle_root = merkle_proxy.witness_merkle_tree().root();

        assert_ne!(merkle_root, witness_merkle_root);

        check_block_tag(&block);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_with_witness_always_different_merkle_witness_root(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let inputs = vec![TxInput::from_utxo(
            OutPointSourceId::Transaction(H256::random_using(&mut rng).into()),
            0,
        )];

        let one_transaction = SignedTransaction::new(
            Transaction::new(0, inputs, Vec::new()).unwrap(),
            vec![InputWitness::NoSignature(Some(b"abc".to_vec()))],
        )
        .expect("invalid witness count");
        let body = BlockBody {
            reward: BlockReward::new(Vec::new()),
            transactions: vec![one_transaction],
        };

        let merkle_root = body.merkle_tree_proxy().unwrap().merkle_tree().root();
        let witness_merkle_root = body.merkle_tree_proxy().unwrap().witness_merkle_tree().root();

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

        let header = header.with_no_signature();

        let block = Block::V1(BlockV1 { header, body });

        check_block_tag(&block);
    }
}

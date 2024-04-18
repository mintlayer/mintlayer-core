// Copyright (c) 2023 RBB S.r.l
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

use merkletree_mintlayer::{
    proof::single::{SingleProofHashes, SingleProofNodes},
    tree::MerkleTree,
};

use crate::primitives::H256;

use super::{
    block_merkle::{calculate_tx_merkle_tree, calculate_witness_merkle_tree},
    merkle_tools::MerkleHasher,
    BlockBody, BlockMerkleTreeError,
};

mod private {
    pub trait PrivateMerkleTreeTag {}
}

pub mod tag {
    pub trait MerkleTreeTag: super::private::PrivateMerkleTreeTag {}
    pub struct WitnessMerkleTree;
    pub struct TxMerkleTree;

    impl MerkleTreeTag for WitnessMerkleTree {}
    impl MerkleTreeTag for TxMerkleTree {}
    impl super::private::PrivateMerkleTreeTag for WitnessMerkleTree {}
    impl super::private::PrivateMerkleTreeTag for TxMerkleTree {}
}

#[must_use]
pub struct BlockBodyMerkleProxy {
    witness_tree: WrappedMerkleTree<tag::WitnessMerkleTree>,
    tree: WrappedMerkleTree<tag::TxMerkleTree>,
}

impl BlockBodyMerkleProxy {
    pub fn new(body: &BlockBody) -> Result<Self, BlockMerkleTreeError> {
        Ok(Self {
            witness_tree: calculate_witness_merkle_tree(body)?.into(),
            tree: calculate_tx_merkle_tree(body)?.into(),
        })
    }

    pub fn witness_merkle_tree(&self) -> &WrappedMerkleTree<tag::WitnessMerkleTree> {
        &self.witness_tree
    }

    pub fn merkle_tree(&self) -> &WrappedMerkleTree<tag::TxMerkleTree> {
        &self.tree
    }
}

/// This struct wrapper is an attempt to create minimal
/// type safety to avoid confusing the two merkle trees, with and without
/// the witness.
#[must_use]
pub struct WrappedMerkleTree<MerkleTreeTag> {
    merkle_tree: MerkleTree<H256, MerkleHasher>,
    _tag: std::marker::PhantomData<MerkleTreeTag>,
}

impl<T: tag::MerkleTreeTag> From<MerkleTree<H256, MerkleHasher>> for WrappedMerkleTree<T> {
    fn from(merkle_tree: MerkleTree<H256, MerkleHasher>) -> Self {
        Self {
            merkle_tree,
            _tag: std::marker::PhantomData,
        }
    }
}

impl<T: tag::MerkleTreeTag> WrappedMerkleTree<T> {
    pub fn root(&self) -> H256 {
        self.merkle_tree.root()
    }

    pub fn raw_tree(&self) -> &MerkleTree<H256, MerkleHasher> {
        &self.merkle_tree
    }

    fn internal_block_reward_leaf(&self) -> H256 {
        *self
            .merkle_tree
            .node_from_bottom(0, 0)
            .expect("Block reward leaf must exist")
            .hash()
    }

    fn internal_transaction_leaf(&self, index: usize) -> Option<H256> {
        self.merkle_tree
            .node_from_bottom(0, index as u32 + 1) // +1 because of block reward leaf
            .map(|n| *n.hash())
    }

    /// The block reward is just an output, hence, no witness exists. Hence,
    /// same method is public for both with and without witness
    pub fn block_reward_inclusion_proof(
        &self,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        // Block reward has index 0 in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&self.merkle_tree, 0)?;

        Ok(proof.into_values())
    }

    fn internal_transaction_inclusion_proof(
        &self,
        index_in_block: u32,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        // We add 1 to the index_in_block because the block reward is the first element in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&self.merkle_tree, index_in_block + 1)?;

        Ok(proof.into_values())
    }
}

impl WrappedMerkleTree<tag::TxMerkleTree> {
    pub fn block_reward_leaf(&self) -> H256 {
        self.internal_block_reward_leaf()
    }

    pub fn transaction_leaf(&self, index: usize) -> Option<H256> {
        self.internal_transaction_leaf(index)
    }

    pub fn transaction_inclusion_proof(
        &self,
        index_in_block: u32,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        self.internal_transaction_inclusion_proof(index_in_block)
    }
}

impl WrappedMerkleTree<tag::WitnessMerkleTree> {
    pub fn block_reward_witness_leaf(&self) -> H256 {
        self.internal_block_reward_leaf()
    }

    pub fn transaction_witness_leaf(&self, index: usize) -> Option<H256> {
        self.internal_transaction_leaf(index)
    }

    pub fn transaction_witness_inclusion_proof(
        &self,
        index_in_block: u32,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        self.internal_transaction_inclusion_proof(index_in_block)
    }
}

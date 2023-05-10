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

use merkletree::{
    proof::single::{SingleProofHashes, SingleProofNodes},
    tree::MerkleTree,
};

use crate::primitives::H256;

use super::{
    block_merkle::{calculate_tx_merkle_tree, calculate_witness_merkle_tree},
    merkle_tools::MerkleHasher,
    BlockBody, BlockMerkleTreeError,
};

#[must_use]
pub struct BlockBodyMerkleProxy {
    witness_tree: WrappedWitnessMerkleTree,
    tree: WrappedMerkleTree,
}

impl BlockBodyMerkleProxy {
    pub fn new(body: &BlockBody) -> Result<Self, BlockMerkleTreeError> {
        Ok(Self {
            witness_tree: calculate_witness_merkle_tree(body)?.into(),
            tree: calculate_tx_merkle_tree(body)?.into(),
        })
    }

    pub fn witness_merkle_tree(&self) -> &WrappedWitnessMerkleTree {
        &self.witness_tree
    }

    pub fn merkle_tree(&self) -> &WrappedMerkleTree {
        &self.tree
    }
}

/// This struct wrapper, and the other one, are an attempt to create minimal
/// type safety to avoid confusing the two merkle trees, with and without
/// the witness.
#[must_use]
pub struct WrappedWitnessMerkleTree {
    witness_merkle_tree: MerkleTree<H256, MerkleHasher>,
}

impl From<MerkleTree<H256, MerkleHasher>> for WrappedWitnessMerkleTree {
    fn from(witness_merkle_tree: MerkleTree<H256, MerkleHasher>) -> Self {
        Self {
            witness_merkle_tree,
        }
    }
}

impl WrappedWitnessMerkleTree {
    pub fn root(&self) -> H256 {
        self.witness_merkle_tree.root()
    }

    pub fn raw_tree(&self) -> &MerkleTree<H256, MerkleHasher> {
        &self.witness_merkle_tree
    }

    pub fn block_reward_witness_leaf(&self) -> H256 {
        *self
            .witness_merkle_tree
            .node_from_bottom(0, 0)
            .expect("Block reward leaf must exist")
            .hash()
    }

    pub fn transaction_witness_leaf(&self, index: usize) -> H256 {
        *self
            .witness_merkle_tree
            .node_from_bottom(0, index as u32 + 1) // +1 because of block reward leaf
            .expect("Transaction witness leaf must exist")
            .hash()
    }

    pub fn block_reward_inclusion_proof(
        &self,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        // Block reward has index 0 in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&self.witness_merkle_tree, 0)?;

        Ok(proof.into_values())
    }

    pub fn transaction_witness_inclusion_proof(
        &self,
        index_in_block: u32,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        // We add 1 to the index_in_block because the block reward is the first element in the block merkle tree
        let proof =
            SingleProofNodes::from_tree_leaf(&self.witness_merkle_tree, index_in_block + 1)?;

        Ok(proof.into_values())
    }
}

/// This struct wrapper, and the other one, are an attempt to create minimal
/// type safety to avoid confusing the two merkle trees, with and without
/// the witness.
#[must_use]
pub struct WrappedMerkleTree {
    merkle_tree: MerkleTree<H256, MerkleHasher>,
}

impl From<MerkleTree<H256, MerkleHasher>> for WrappedMerkleTree {
    fn from(merkle_tree: MerkleTree<H256, MerkleHasher>) -> Self {
        Self { merkle_tree }
    }
}

impl WrappedMerkleTree {
    pub fn root(&self) -> H256 {
        self.merkle_tree.root()
    }

    pub fn raw_tree(&self) -> &MerkleTree<H256, MerkleHasher> {
        &self.merkle_tree
    }

    pub fn block_reward_leaf(&self) -> H256 {
        *self
            .merkle_tree
            .node_from_bottom(0, 0)
            .expect("Block reward leaf must exist")
            .hash()
    }

    pub fn transaction_leaf(&self, index: usize) -> H256 {
        *self
            .merkle_tree
            .node_from_bottom(0, index as u32 + 1) // +1 because of block reward leaf
            .expect("Transaction witness leaf must exist")
            .hash()
    }

    pub fn block_reward_inclusion_proof(
        &self,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        // Block reward has index 0 in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&self.merkle_tree, 0)?;

        Ok(proof.into_values())
    }

    pub fn transaction_inclusion_proof(
        &self,
        index_in_block: u32,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        // We add 1 to the index_in_block because the block reward is the first element in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&self.merkle_tree, index_in_block + 1)?;

        Ok(proof.into_values())
    }
}

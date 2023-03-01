// Copyright (c) 2021-2023 RBB S.r.l
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

use crate::primitives::H256;

use super::super::{
    tree::{MerkleTree, Node},
    MerkleTreeProofExtractionError,
};

/// A proof for a single leaf in a Merkle tree. The proof contains the leaf and the branch of the tree.
/// This is considered an intermediary object. For storage, use `SingleProofHashes` through
/// `SingleProofNodes::into_values()`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleProofNodes<'a> {
    leaf: Node<'a>,
    branch: Vec<Node<'a>>,
}

impl<'a> SingleProofNodes<'a> {
    /// Creates a proof for a leaf by its index in the lowest level (the tip).
    /// A proof doesn't contain the root.
    pub fn from_tree_leaf(
        tree: &'a MerkleTree,
        leaf_index: usize,
    ) -> Result<Self, MerkleTreeProofExtractionError> {
        let leaf_count = tree.leaf_count().get();
        if leaf_index > leaf_count {
            return Err(MerkleTreeProofExtractionError::LeafIndexOutOfRange(
                leaf_index, leaf_count,
            ));
        }

        let leaf = tree.node_from_bottom(0, leaf_index).ok_or(
            MerkleTreeProofExtractionError::AccessError(
                crate::primitives::merkle::MerkleTreeAccessError::AbsIndexOutOfRange(
                    leaf_index,
                    tree.total_node_count().get(),
                ),
            ),
        )?;

        let proof: Vec<_> = leaf.into_iter_parents().map_while(|n| n.sibling()).collect();

        assert_eq!(
            proof.len(),
            tree.level_count().get() - 1,
            "This happens only if the we fail to find a sibling, which is only for root. In the loop, this cannot happen, so siblings must exist"
        );

        let result = Self {
            leaf,
            branch: proof,
        };

        Ok(result)
    }

    pub fn into_values(self) -> SingleProofHashes {
        let proof = self.branch.into_iter().map(|node| *node.hash()).collect::<Vec<_>>();
        let leaf_abs_index = self.leaf.into_position().position().1 as u32;
        SingleProofHashes {
            leaf_index_in_level: leaf_abs_index,
            branch: proof,
        }
    }

    pub fn into_nodes(self) -> Vec<Node<'a>> {
        self.branch
    }

    pub fn branch(&self) -> &[Node<'a>] {
        &self.branch
    }

    pub fn leaf(&self) -> Node<'a> {
        self.leaf
    }
}

/// Same as `SingleProofNodes`, but has only hashes and leaf index in the lowest level.
/// This is the minimum information required to prove that the given leaf can produce the root's hash.
/// This struct is supposed to be serialized, unlike `SingleProofNodes`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleProofHashes {
    leaf_index_in_level: u32,
    branch: Vec<H256>,
}

impl SingleProofHashes {
    pub fn into_hashes(self) -> Vec<H256> {
        self.branch
    }

    pub fn branch(&self) -> &[H256] {
        &self.branch
    }

    pub fn leaf_index_in_level(&self) -> u32 {
        self.leaf_index_in_level
    }

    /// Verifies that the given leaf can produce the root's hash.
    /// Returns None if the proof is empty (the tree has only one node),
    /// as this function then boils down to `leaf == root`, which is trivial.
    /// This choice, to return None, is a security measure to prevent a malicious user from
    /// circumventing verification by providing a proof of a single node.
    pub fn verify(&self, leaf: H256, root: H256) -> Option<bool> {
        // in case it's a single-node tree, we don't need to verify or hash anything
        if self.branch.is_empty() {
            return None;
        }

        let hash = self.branch.iter().enumerate().fold(leaf, |prev_hash, (index, sibling)| {
            let node_in_level_index = self.leaf_index_in_level >> index;
            if node_in_level_index % 2 == 0 {
                MerkleTree::hash_pair(&prev_hash, sibling)
            } else {
                MerkleTree::hash_pair(sibling, &prev_hash)
            }
        });

        Some(hash == root)
    }
}

#[cfg(test)]
mod tests;

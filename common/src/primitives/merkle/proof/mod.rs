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

use super::{
    tree::{MerkleTree, Node},
    MerkleTreeProofExtractionError,
};

/// A proof for a single leaf in a Merkle tree. The proof contains the leaf and the branch of the tree.
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
        let leaves_count = tree.leaves_count().get();
        if leaf_index > leaves_count {
            return Err(MerkleTreeProofExtractionError::LeafIndexOutOfRange(
                leaf_index,
                leaves_count,
            ));
        }

        let leaf = tree.node_from_bottom(0, leaf_index)?;

        let mut last_node = leaf;
        let mut proof = vec![];
        // once we reach root we stop
        while !last_node.is_root() {
            // We push siblings of parents because they're what we need to calculate the root, upwards.
            let sibling = last_node.sibling().unwrap();
            proof.push(sibling);

            last_node = last_node.parent().expect("This can never be root");
        }

        let result = Self {
            leaf,
            branch: proof,
        };

        Ok(result)
    }

    pub fn into_values(self) -> SingleProofHashes {
        let proof = self.branch.into_iter().map(|node| *node.hash()).collect::<Vec<_>>();
        let leaf_abs_index = self.leaf.position().1 as u32;
        SingleProofHashes {
            leaf_index_in_level: leaf_abs_index,
            branch: proof,
        }
    }

    pub fn into_nodes(self) -> Vec<Node<'a>> {
        self.branch
    }

    pub fn proof(&self) -> &[Node<'a>] {
        &self.branch
    }

    pub fn verify(&self, leaf: H256, root: H256) -> bool {
        self.clone().into_values().verify(leaf, root)
    }
}

/// Same as SingleProofNodes, but has only hashes and leaf index in the lowest level.
/// This is the minimum information required to prove that the given leaf can produce the root's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleProofHashes {
    leaf_index_in_level: u32,
    branch: Vec<H256>,
}

impl SingleProofHashes {
    pub fn into_hashes(self) -> Vec<H256> {
        self.branch
    }

    pub fn verify(&self, leaf: H256, root: H256) -> bool {
        let mut hash = leaf;
        let mut proof_index = 0;
        let mut curr_leaf_index = self.leaf_index_in_level as usize;

        // in case it's a single-node tree, we don't need to verify or hash anything
        if self.branch.len() == 0 {
            return hash == root;
        }

        loop {
            let sibling = self.branch[proof_index];
            let parent_hash = if curr_leaf_index % 2 == 0 {
                MerkleTree::combine_pair(&hash, &sibling)
            } else {
                MerkleTree::combine_pair(&sibling, &hash)
            };

            // move to the next level
            hash = parent_hash;
            proof_index += 1;
            curr_leaf_index /= 2;

            // the last hash in the proof is the one right before root, hence hashing will result in root's hash
            if proof_index >= self.branch.len() {
                return parent_hash == root;
            }
        }
    }
}

#[cfg(test)]
mod tests;

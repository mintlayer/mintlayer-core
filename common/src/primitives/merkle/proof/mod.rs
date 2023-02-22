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
    pos::NodePosition,
    tree::{MerkleTree, Node},
    MerkleTreeProofExtractionError,
};

pub struct SingleProofNodes<'a> {
    leaf: Node<'a>,
    proof: Vec<Node<'a>>,
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

        let result = Self { leaf, proof };

        Ok(result)
    }

    pub fn into_values(self) -> SingleProofHashes {
        let proof = self.proof.into_iter().map(|node| *node.hash()).collect::<Vec<_>>();
        let leaf_abs_index = self.leaf.abs_index() as u32;
        SingleProofHashes {
            leaf_abs_index,
            proof,
        }
    }

    pub fn into_nodes(self) -> Vec<Node<'a>> {
        self.proof
    }

    pub fn proof(&self) -> &[Node<'a>] {
        &self.proof
    }

    pub fn verify(&self, leaf: H256, root: H256) -> bool {
        let node_pos = NodePosition::from_abs_index(
            self.leaf.tree().total_node_count(),
            self.leaf.abs_index(),
        )
        .expect("Starting position cannot be invalid");

        let mut hash = leaf;
        let mut node_pos = node_pos;
        let mut proof_index = 0;

        // in case it's a single-node tree, we don't need to verify or hash anything
        if self.proof.len() == 0 {
            return hash == root;
        }

        loop {
            let sibling = self.proof[proof_index].hash();
            let parent_hash = if node_pos.is_left() {
                MerkleTree::combine_pair(&hash, sibling)
            } else {
                MerkleTree::combine_pair(sibling, &hash)
            };

            hash = parent_hash;
            node_pos = node_pos.parent().expect("Should never happen");
            proof_index += 1;

            if node_pos.is_root() {
                return parent_hash == root;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleProofHashes {
    leaf_abs_index: u32,
    proof: Vec<H256>,
}

impl SingleProofHashes {
    pub fn into_hashes(self) -> Vec<H256> {
        self.proof
    }
}

#[cfg(test)]
mod tests;

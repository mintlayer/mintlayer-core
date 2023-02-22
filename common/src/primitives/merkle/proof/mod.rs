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
    /// A proof doesn't contain the root. Hence, passing a tree with only the root
    /// returns Ok(None).
    pub fn from_tree_leaf(
        tree: &'a MerkleTree,
        leaf_index: usize,
    ) -> Result<Option<Self>, MerkleTreeProofExtractionError> {
        let leaves_count = tree.leaves_count().get();
        if leaf_index > leaves_count {
            return Err(MerkleTreeProofExtractionError::LeafIndexOutOfRange(
                leaf_index,
                leaves_count,
            ));
        }

        let leaf = tree.node_from_bottom(0, leaf_index)?;
        if leaf.is_root() {
            return Ok(None);
        }

        let mut last_node = leaf;
        let mut proof = vec![leaf.sibling().expect("There must be a sibling, this isn't root")];
        loop {
            let err_msg = "Should never happen because we break on root and never start with root";
            last_node = last_node.parent().expect(err_msg);
            if last_node.is_root() {
                break;
            }
            // We push siblings of parents because they're what we need to calculate the root, upwards.
            let sibling = last_node.sibling().unwrap();
            proof.push(sibling);
        }

        let result = Self { leaf, proof };

        Ok(Some(result))
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

    pub fn verify(&self) -> bool {
        let _node_pos = NodePosition::from_abs_index(
            self.leaf.tree().total_node_count(),
            self.leaf.abs_index(),
        );

        todo!()
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

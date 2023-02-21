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

pub struct SingleProofNodes<'a> {
    pub proof: Vec<Node<'a>>,
}

impl<'a> SingleProofNodes<'a> {
    /// Nodes are hashed in a specific order. We order them here.
    fn order_pair<'b>((left, right): (Node<'b>, Node<'b>)) -> (Node<'b>, Node<'b>) {
        if left.abs_index() < right.abs_index() {
            (left, right)
        } else {
            (right, left)
        }
    }

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

        let mut proof = vec![leaf];
        let mut last_node = leaf;
        loop {
            let err_msg = "Should never happen because we break on root";
            let curr_node = last_node.parent().expect(err_msg);
            if curr_node.is_root() {
                break;
            }
            let sibling = curr_node.sibling().unwrap();
            let (left, right) = Self::order_pair((last_node, sibling));
            proof.push(left);
            proof.push(right);
            last_node = curr_node;
        }

        let result = Self { proof };

        Ok(Some(result))
    }

    pub fn into_values(self) -> SingleProofHashes {
        let proof = self.proof.into_iter().map(|node| *node.hash()).collect::<Vec<_>>();
        SingleProofHashes { proof }
    }

    pub fn into_nodes(self) -> Vec<Node<'a>> {
        self.proof
    }
}

pub struct SingleProofHashes {
    pub proof: Vec<H256>,
}

impl SingleProofHashes {
    pub fn into_hashes(self) -> Vec<H256> {
        self.proof
    }
}

#[cfg(test)]
mod tests;

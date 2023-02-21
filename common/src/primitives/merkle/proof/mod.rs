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

pub struct SingleProof {
    pub leaf: H256,
    pub proof: Vec<H256>,
}

impl SingleProof {
    /// Nodes are hashed in a specific order. We order them here.
    fn order_pair<'a>((left, right): (Node<'a>, Node<'a>)) -> (Node<'a>, Node<'a>) {
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
        tree: &MerkleTree,
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

        let mut proof = Vec::new();
        let mut last_node = leaf;
        loop {
            let err_msg = "Should never happen because we break on root";
            let curr_node = last_node.parent().expect(err_msg);
            if curr_node.is_root() {
                break;
            }
            let sibling = curr_node.sibling().unwrap();
            let (left, right) = Self::order_pair((last_node, sibling));
            proof.push(*left.value());
            proof.push(*right.value());
            last_node = curr_node;
        }

        let result = Self {
            leaf: *leaf.value(),
            proof,
        };

        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests;

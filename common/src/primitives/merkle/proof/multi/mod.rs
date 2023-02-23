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

mod ordered_node;

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
};

use itertools::Itertools;

use crate::primitives::{
    merkle::{
        tree::{MerkleTree, Node},
        MerkleTreeProofExtractionError,
    },
    H256,
};

use self::ordered_node::NodeWithAbsOrder;

use super::single::SingleProofNodes;

// Merkle proofs for multiple leaves.
#[must_use]
#[derive(Debug, Clone)]
pub struct MultiProofNodes<'a> {
    /// The leaves where the calculation upwards to the root hash will start
    proof_leaves: Vec<Node<'a>>,
    /// The minimal set of nodes needed to recreate the root hash (in addition to the leaves)
    nodes: Vec<Node<'a>>,
    /// The number of leaves in the tree, from which this proof was extracted
    tree_leaves_count: NonZeroUsize,
}

/// Ensure the leaves indices are sorted and unique
fn is_sorted_and_unique(leaves_indices: &[usize]) -> bool {
    leaves_indices.iter().tuple_windows::<(&usize, &usize)>().all(|(i, j)| i < j)
}

impl<'a> MultiProofNodes<'a> {
    pub fn from_tree_leaves(
        tree: &'a MerkleTree,
        leaves_indices: &[usize],
    ) -> Result<Self, MerkleTreeProofExtractionError> {
        if leaves_indices.is_empty() {
            return Err(MerkleTreeProofExtractionError::NoLeavesToCreateProof);
        }

        if !is_sorted_and_unique(leaves_indices) {
            return Err(
                MerkleTreeProofExtractionError::UnsortedOrUniqueLeavesIndices(
                    leaves_indices.to_vec(),
                ),
            );
        }

        {
            let leaves_count = tree.leaves_count();

            if leaves_indices.iter().any(|v| *v >= leaves_count.get()) {
                return Err(MerkleTreeProofExtractionError::IndexOutOfRange(
                    leaves_indices.to_vec(),
                    leaves_count.get(),
                ));
            }
        }

        let single_proofs = leaves_indices
            .iter()
            .map(|i| SingleProofNodes::from_tree_leaf(tree, *i))
            .collect::<Result<Vec<_>, _>>()?;

        let mut level = 0;
        let mut computed_from_prev_level = vec![];
        let mut proof = vec![];

        let level_count = tree.level_count();

        while level < level_count.get() - 1 {
            let leaves = single_proofs.iter().map(|sp| sp.branch()[level]).collect::<Vec<_>>();

            let siblings = single_proofs
                .iter()
                .map(|sp| {
                    (
                        sp.branch()[level].sibling().unwrap().abs_index(),
                        sp.branch()[level].sibling().unwrap(),
                    )
                })
                .collect::<BTreeMap<usize, Node<'a>>>();

            // We remove leaves that are already in siblings because they will come from the verification input.
            // This happens when the leaves, for which a proof is requested, are used together to build a parent node
            // in the tree. In that case, given that the verification will have both as inputs, we don't need to include
            // them in the proof.
            // We also remove the nodes that can be computed from the previous level, because they will be included in the proof
            let proofs_at_level = leaves
                .into_iter()
                .filter(|node| !siblings.contains_key(&node.abs_index()))
                .filter(|node| !computed_from_prev_level.contains(&node.abs_index()))
                .map(NodeWithAbsOrder::from)
                .collect::<BTreeSet<_>>();

            // We collect all the nodes that can be computed from this level, and will use it in the next iteration
            computed_from_prev_level = proofs_at_level
                .iter()
                .map(|n| n.get())
                .tuple_windows::<(&Node, &Node)>()
                .filter(|n| n.0.abs_index() % 2 == 0 && n.0.abs_index() + 1 == n.1.abs_index())
                .map(|(n1, _n2)| n1.parent().unwrap().abs_index())
                .collect();

            proof.extend(proofs_at_level.into_iter().map(Node::from));

            level += 1;
        }

        Ok(Self {
            proof_leaves: leaves_indices
                .iter()
                .map(|i| tree.node_from_bottom(0, *i).expect("Leaves already checked"))
                .collect(),
            nodes: proof,
            tree_leaves_count: tree.leaves_count(),
        })
    }

    pub fn nodes(&self) -> &[Node<'a>] {
        &self.nodes
    }

    pub fn proof_leaves(&self) -> &[Node<'a>] {
        &self.proof_leaves
    }

    pub fn tree_leaves_count(&self) -> NonZeroUsize {
        self.tree_leaves_count
    }

    pub fn into_values(self) -> MultiProofHashes {
        MultiProofHashes {
            nodes: self.nodes.into_iter().map(|n| (n.abs_index(), *n.hash())).collect(),
            tree_leaves_count: self.proof_leaves[0].tree().leaves_count(),
        }
    }
}

#[must_use]
#[derive(Debug, Clone)]
pub struct MultiProofHashes {
    /// The minimal set of nodes needed to recreate the root hash (in addition to the leaves)
    nodes: BTreeMap<usize, H256>,
    /// The number of leaves in the tree, from which this proof was extracted
    tree_leaves_count: NonZeroUsize,
}

impl MultiProofHashes {
    pub fn nodes(&self) -> &BTreeMap<usize, H256> {
        &self.nodes
    }

    pub fn tree_leaves_count(&self) -> NonZeroUsize {
        self.tree_leaves_count
    }

    /// Given a set of leaves and their indices, verify that the root hash is correct
    pub fn verify(&self, leaves: BTreeMap<usize, H256>, root: H256) -> Option<bool> {
        // in case it's a single-node tree, we don't need to verify or hash anything
        // TODO(PR): Maybe return an error instead?
        if self.nodes.is_empty() {
            return None;
        }

        if leaves.is_empty() {
            return None;
            // no leaves provided
        }

        if self.tree_leaves_count.get().count_ones() != 1 {
            // Must be a power of two
            return None;
        }

        if leaves.iter().any(|(index, _hash)| *index >= self.tree_leaves_count.get()) {
            // One or more indices are out of range
            return None;
        }

        let tree_size = self.tree_leaves_count.get() * 2 - 1;
        let level_count = tree_size.trailing_ones() as usize;

        if self.nodes.iter().any(|(index, _hash)| *index >= tree_size) {
            // One ore more nodes index is out of range
            return None;
        }

        let leaf_sibling_index = |leaf_index: usize| {
            if leaf_index % 2 == 0 {
                leaf_index + 1
            } else {
                leaf_index - 1
            }
        };

        let all_nodes = self.nodes.iter().chain(leaves.iter()).collect::<BTreeMap<_, _>>();

        let mut result = true;

        for (leaf_index_in_level, leaf_hash) in &leaves {
            let mut hash = *leaf_hash;
            let mut curr_leaf_index = *leaf_index_in_level;
            let mut proof_level_index = 0;

            loop {
                let sibling_index = leaf_sibling_index(curr_leaf_index);
                let sibling = match all_nodes.get(&sibling_index) {
                    Some(sibling) => *sibling,
                    None => return None, // Sibling not found error / incomplete proof
                };
                let parent_hash = if curr_leaf_index % 2 == 0 {
                    MerkleTree::combine_pair(&hash, sibling)
                } else {
                    MerkleTree::combine_pair(sibling, &hash)
                };

                // move to the next level
                hash = parent_hash;
                curr_leaf_index /= 2;
                proof_level_index += 1;

                result |= parent_hash == root;

                // the last hash in the proof is the one right before root, hence hashing will result in root's hash
                if proof_level_index + 1 >= level_count {
                    break;
                }
            }
        }

        Some(result)
    }
}

#[cfg(test)]
mod tests;

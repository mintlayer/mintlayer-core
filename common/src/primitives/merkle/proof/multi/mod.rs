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
        pos::NodePosition,
        tree::{tree_size::TreeSize, MerkleTree, Node},
        MerkleProofVerificationError, MerkleTreeProofExtractionError,
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
    tree_leaf_count: NonZeroUsize,
}

/// Ensure the leaves indices are sorted and unique
fn is_sorted_and_unique(leaves_indices: &[usize]) -> bool {
    leaves_indices.iter().tuple_windows::<(&usize, &usize)>().all(|(i, j)| i < j)
}

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    if v.is_empty() {
        return Vec::new();
    }
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().expect("Iter is in tandem. Should never happen."))
                .collect::<Vec<T>>()
        })
        .collect()
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
            let leaf_count = tree.leaf_count();

            if leaves_indices.iter().any(|v| *v >= leaf_count.get()) {
                return Err(MerkleTreeProofExtractionError::IndexOutOfRange(
                    leaves_indices.to_vec(),
                    leaf_count.get(),
                ));
            }
        }

        let single_proofs = leaves_indices
            .iter()
            .map(|i| SingleProofNodes::from_tree_leaf(tree, *i))
            .collect::<Result<Vec<_>, _>>()?;

        let mut computed_from_prev_level = vec![];
        let mut proof = vec![];

        let single_proofs_branches = single_proofs
            .clone()
            .into_iter()
            .map(|sp| sp.branch().to_vec())
            .collect::<Vec<_>>();

        // We expect all proofs to have the same branch lengths
        if !single_proofs_branches.is_empty()
            && !single_proofs_branches
                .iter()
                .all(|v| v.len() == single_proofs_branches[0].len())
        {
            panic!("Proofs of the same tree are all expected to have the same length")
        }

        // Proofs have branches that extend from leaves to the root, but they never reach the root.
        // We want to loop on the tree level, hence we transpose the branches of the single proofs
        let single_proofs_levels = transpose(single_proofs_branches);

        for nodes_of_level in single_proofs_levels {
            let sibling_err =
                "Only root has no sibling. We are never at root here, so this should never happen.";
            let siblings = nodes_of_level
                .iter()
                .map(|node| node.sibling().expect(sibling_err).abs_index())
                .collect::<BTreeSet<usize>>();

            // We remove leaves that are already in siblings because they will come from the verification input.
            // This happens when the leaves, for which a proof is requested, are used together to build a parent node
            // in the tree. In that case, given that the verification will have both as inputs, we don't need to include
            // them in the proof.
            // We also remove the nodes that can be computed from the previous level, because they will be included in the proof
            let proofs_at_level = nodes_of_level
                .into_iter()
                .filter(|node| !siblings.contains(&node.abs_index()))
                .filter(|node| !computed_from_prev_level.contains(&node.abs_index()))
                .map(NodeWithAbsOrder::from)
                .collect::<BTreeSet<_>>();

            // We collect all the nodes that can be computed from this level, and will use it in the next iteration
            let parent_err = "We should never be at root, so there should always be a parent";
            computed_from_prev_level = proofs_at_level
                .iter()
                .map(|n| n.get())
                .tuple_windows::<(&Node, &Node)>()
                .filter(|n| n.0.abs_index() % 2 == 0 && n.0.abs_index() + 1 == n.1.abs_index())
                .map(|(n1, _n2)| n1.parent().expect(parent_err).abs_index())
                .collect();

            proof.extend(proofs_at_level.into_iter().map(Node::from));
        }

        Ok(Self {
            proof_leaves: leaves_indices
                .iter()
                .map(|i| tree.node_from_bottom(0, *i).expect("Leaves already checked"))
                .collect(),
            nodes: proof,
            tree_leaf_count: tree.leaf_count(),
        })
    }

    pub fn nodes(&self) -> &[Node<'a>] {
        &self.nodes
    }

    pub fn proof_leaves(&self) -> &[Node<'a>] {
        &self.proof_leaves
    }

    pub fn tree_leaf_count(&self) -> NonZeroUsize {
        self.tree_leaf_count
    }

    pub fn into_values(self) -> MultiProofHashes {
        MultiProofHashes {
            nodes: self.nodes.into_iter().map(|n| (n.abs_index(), *n.hash())).collect(),
            tree_leaf_count: self.proof_leaves[0].tree().leaf_count(),
        }
    }
}

#[must_use]
#[derive(Debug, Clone)]
pub struct MultiProofHashes {
    /// The minimal set of nodes needed to recreate the root hash (in addition to the leaves)
    nodes: BTreeMap<usize, H256>,
    /// The number of leaves in the tree, from which this proof was extracted
    tree_leaf_count: NonZeroUsize,
}

impl MultiProofHashes {
    pub fn nodes(&self) -> &BTreeMap<usize, H256> {
        &self.nodes
    }

    pub fn tree_leaf_count(&self) -> NonZeroUsize {
        self.tree_leaf_count
    }

    /// While verifying the multi-proof, we need to precalculate all the possible nodes that are required to build the root hash.
    fn calculate_missing_nodes(
        tree_size: TreeSize,
        input: BTreeMap<&usize, &H256>,
    ) -> BTreeMap<usize, H256> {
        let mut result =
            input.into_iter().map(|(a, b)| (*a, *b)).collect::<BTreeMap<usize, H256>>();
        for index in 0..tree_size.get() - 1 {
            if !result.contains_key(&index) || !result.contains_key(&(index + 1)) {
                continue;
            }

            let err = "We never reach the root as per the loop's range, so this should always work";

            let node_l = NodePosition::from_abs_index(tree_size, index).expect(err);
            let node_r = NodePosition::from_abs_index(tree_size, index + 1).expect(err);

            if node_l.is_left() && node_r.is_right() {
                let parent = node_l.parent().expect("Cannot be root because of loop range");
                let hash = MerkleTree::combine_pair(&result[&index], &result[&(index + 1)]);

                result.insert(parent.abs_index(), hash);
            }
        }

        result
    }

    /// Given a set of leaves and their indices, verify that the root hash is correct
    /// Returns Ok(None) if the proof is empty (i.e. the tree has only one node)
    /// This choice, to return None, is a security measure to prevent a malicious user from
    /// circumventing verification by providing a proof of a single node.
    pub fn verify(
        &self,
        leaves: BTreeMap<usize, H256>,
        root: H256,
    ) -> Result<Option<bool>, MerkleProofVerificationError> {
        // in case it's a single-node tree, we don't need to verify or hash anything

        if leaves.is_empty() {
            return Err(MerkleProofVerificationError::LeavesContainerProvidedIsEmpty);
        }

        if self.tree_leaf_count.get().count_ones() != 1 {
            return Err(MerkleProofVerificationError::InvalidTreeLeavesCount(
                self.tree_leaf_count().get(),
            ));
        }

        if leaves.iter().any(|(index, _hash)| *index >= self.tree_leaf_count.get()) {
            return Err(MerkleProofVerificationError::LeavesIndicesOutOfRange(
                leaves.keys().cloned().collect(),
                self.tree_leaf_count.get(),
            ));
        }

        let tree_size = TreeSize::from_value(self.tree_leaf_count.get() * 2 - 1)
            .expect("Already proven from source");

        if self.nodes.iter().any(|(index, _hash)| *index >= tree_size.get()) {
            return Err(MerkleProofVerificationError::NodesIndicesOutOfRange(
                self.nodes.keys().cloned().collect(),
                tree_size.get(),
            ));
        }

        let all_nodes = self.nodes.iter().chain(leaves.iter()).collect::<BTreeMap<_, _>>();
        let all_nodes = MultiProofHashes::calculate_missing_nodes(tree_size, all_nodes);

        // Result is Option<bool> because it must pass through the loop inside at least once; other nothing is checked
        let mut result = None;

        // Verify the root for every leaf we got
        // Note: This can be made more efficient by marking "hashed" nodes and skipping them,
        // but we don't care about performance here. We care more about security.
        for (leaf_index, leaf_hash) in &leaves {
            let mut hash = *leaf_hash;
            // let mut curr_leaf_index = *leaf_index_in_level;
            let mut curr_node_pos = NodePosition::from_position(tree_size, 0, *leaf_index)
                .expect("At level zero, leave index be valid");

            // In this loop we move up the tree, combining the hashes of the current node with its sibling
            while !curr_node_pos.is_root() {
                let sibling_index =
                    curr_node_pos.sibling().expect("This cannot be root").abs_index();
                let sibling = match all_nodes.get(&sibling_index) {
                    Some(sibling) => *sibling,
                    None => {
                        return Err(MerkleProofVerificationError::RequiredNodeMissing(
                            sibling_index,
                        ))
                    }
                };
                let parent_hash = if curr_node_pos.is_left() {
                    MerkleTree::combine_pair(&hash, &sibling)
                } else {
                    MerkleTree::combine_pair(&sibling, &hash)
                };

                // move to the next level
                let err_msg = "We can never be at root yet as we checked in the loop entry";
                curr_node_pos = curr_node_pos.parent().expect(err_msg);
                hash = parent_hash;

                // If the next iteration is going to be the root, check if the root hash is correct and exit the inner loop
                if curr_node_pos.is_root() {
                    result = match result {
                        Some(r) => Some(r | (parent_hash == root)),
                        None => Some(parent_hash == root),
                    };

                    break;
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests;

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

use crate::merkle::hasher::PairHasher;

use super::{
    super::{
        tree::{MerkleTree, Node},
        MerkleTreeProofExtractionError,
    },
    verify_result::ProofVerifyResult,
};

/// A proof for a single leaf in a Merkle tree. The proof contains the leaf and the branch of the tree.
/// This is considered an intermediary object. For storage, use `SingleProofHashes` through
/// `SingleProofNodes::into_values()`.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct SingleProofNodes<'a, T, H> {
    leaf: Node<'a, T, H>,
    branch: Vec<Node<'a, T, H>>,
}

impl<T, H> Clone for SingleProofNodes<'_, T, H> {
    fn clone(&self) -> Self {
        Self { leaf: self.leaf, branch: self.branch.clone() }
    }
}

impl<'a, T: Clone, H: PairHasher<Type = T>> SingleProofNodes<'a, T, H> {
    pub fn into_nodes(self) -> Vec<Node<'a, T, H>> {
        self.branch
    }

    pub fn branch(&self) -> &[Node<'a, T, H>] {
        &self.branch
    }

    pub fn leaf(&self) -> Node<'a, T, H> {
        self.leaf
    }
}

impl<'a, T: Clone, H: PairHasher<Type = T>> SingleProofNodes<'a, T, H> {
    /// Creates a proof for a leaf by its index in the lowest level (the tip).
    /// A proof doesn't contain the root.
    pub fn from_tree_leaf(
        tree: &'a MerkleTree<T, H>,
        leaf_index: u32,
    ) -> Result<Self, MerkleTreeProofExtractionError> {
        let leaf_count = tree.leaf_count().get();
        if leaf_index > leaf_count {
            return Err(MerkleTreeProofExtractionError::LeafIndexOutOfRange(
                leaf_index, leaf_count,
            ));
        }

        let leaf = tree.node_from_bottom(0, leaf_index).ok_or(
            MerkleTreeProofExtractionError::AccessError(
                crate::merkle::MerkleTreeAccessError::AbsIndexOutOfRange(
                    leaf_index,
                    tree.total_node_count().get(),
                ),
            ),
        )?;

        let proof: Vec<_> = leaf.into_iter_parents().map_while(|n| n.sibling()).collect();

        assert_eq!(
            proof.len() as u32,
            tree.level_count().get()  - 1,
            "This happens only if the we fail to find a sibling, which is only for root. In the loop, this cannot happen, so siblings must exist"
        );

        let result = Self { leaf, branch: proof };

        Ok(result)
    }

    pub fn into_values(self) -> SingleProofHashes<T, H> {
        let proof = self.branch.into_iter().map(|node| node.hash().clone()).collect::<Vec<_>>();
        let leaf_abs_index = self.leaf.into_position().position().1;
        SingleProofHashes {
            leaf_index_in_level: leaf_abs_index,
            branch: proof,
            _hasher: std::marker::PhantomData,
        }
    }
}

/// Same as `SingleProofNodes`, but has only hashes and leaf index in the lowest level.
/// This is the minimum information required to prove that the given leaf can produce the root's hash.
/// This struct is supposed to be serialized, unlike `SingleProofNodes`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
pub struct SingleProofHashes<T, H> {
    leaf_index_in_level: u32,
    branch: Vec<T>,
    _hasher: std::marker::PhantomData<H>,
}

impl<T: Eq, H: PairHasher<Type = T>> SingleProofHashes<T, H> {
    pub fn into_hashes(self) -> Vec<T> {
        self.branch
    }

    pub fn branch(&self) -> &[T] {
        &self.branch
    }

    pub fn leaf_index_in_level(&self) -> u32 {
        self.leaf_index_in_level
    }
}

impl<T: Eq, H: PairHasher<Type = T>> SingleProofHashes<T, H> {
    /// Verifies that the given leaf can produce the root's hash.
    pub fn verify(&self, leaf: T, root: T) -> ProofVerifyResult {
        // in case it's a single-node tree, we don't need to verify or hash anything
        if self.branch.is_empty() {
            return match leaf == root {
                true => ProofVerifyResult::PassedTrivially,
                false => ProofVerifyResult::Failed,
            };
        }

        let hash = self.branch.iter().enumerate().fold(leaf, |prev_hash, (index, sibling)| {
            let node_in_level_index = self.leaf_index_in_level >> index;
            if node_in_level_index % 2 == 0 {
                H::hash_pair(&prev_hash, sibling)
            } else {
                H::hash_pair(sibling, &prev_hash)
            }
        });

        match hash == root {
            true => ProofVerifyResult::PassedDecisively,
            false => ProofVerifyResult::Failed,
        }
    }
}

#[cfg(test)]
mod tests;

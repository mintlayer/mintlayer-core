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

pub mod padding;
pub mod tree_size;

use std::num::NonZeroUsize;

use crypto::hash::StreamHasher;

use crate::primitives::{
    id::{default_hash, DefaultHashAlgoStream},
    H256,
};

use self::{padding::IncrementalPaddingIterator, tree_size::TreeSize};

use super::{pos::NodePosition, MerkleTreeAccessError, MerkleTreeFormError};

/// Merkle tree in the form of a vector, where the bottom leaves first, from left to right, and the root is
/// the last element.
/// Definitions:
/// - Leaf: A node does not have children.
/// - Node: any element of the tree.
/// - Absolute index: The data structure that represents the tree internally is a Vec.
///   Leaves start from 0 and from the left and end at the right, then next, higher levels. The last element is the root.
///   The absolute index is the index to find a specific node in this tree, regardless of where it lies.
/// - Position: The "coordinates" to find a node, given as level (leaves are at level 0, root is highest level),
///   and index (we count from left to right).
/// - Root: The root of the tree; in merkle-tree's case, it's the node that's created by hashing all the elements underneath.
/// - Padding: Extra elements we add to the tree to make the number of leaves a power of 2. This has to match some security specs.
///
/// Given that this is strictly a filled-up binary tree, the number of leaves is always a power of 2, and the total number of
/// nodes is always 2 * leaves - 1. These are invariants that are always held through type-level checks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MerkleTree {
    tree: Vec<H256>,
}

impl MerkleTree {
    pub(super) fn hash_pair(left: &H256, right: &H256) -> H256 {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(left.as_bytes());
        hasher.write(right.as_bytes());
        H256::from(hasher.finalize())
    }

    fn create_tree_from_leaves(
        leaves: impl IntoIterator<Item = H256>,
    ) -> Result<Vec<H256>, MerkleTreeFormError> {
        let mut tree = leaves.into_iter().collect::<Vec<_>>();
        if tree.is_empty() {
            return Err(MerkleTreeFormError::TooSmall(tree.len()));
        }
        let steps = tree.len() - 1;
        tree.reserve(steps); // reserve another tree.len() - 1 elements (the rest of the tree after the leaves)
        for i in 0..steps {
            let el = Self::hash_pair(&tree[i * 2], &tree[i * 2 + 1]);
            tree.push(el);
        }

        Ok(tree)
    }

    /// Create a new merkle tree from a list of leaves, and padding with incremental padding if needed.
    /// Incremental padding means that the padding is created by hashing the last element of the list,
    /// and then hashing the result with the next element of the list, and so on.
    pub fn from_leaves(
        leaves: impl IntoIterator<Item = H256>,
    ) -> Result<Self, MerkleTreeFormError> {
        let pad_f = |i: &H256| default_hash(i);

        let padded_leaves_iter = IncrementalPaddingIterator::new(leaves.into_iter(), pad_f);

        let tree = Self::create_tree_from_leaves(padded_leaves_iter)?;

        TreeSize::from_value(tree.len()).expect("Invalid tree size. Invariant broken.");
        let res = Self { tree };
        Ok(res)
    }

    pub fn root(&self) -> H256 {
        *self.tree.last().expect("By design, at least one element must exist")
    }

    pub fn total_node_count(&self) -> TreeSize {
        self.tree
            .len()
            .try_into()
            .expect("(total_node_count) By design, tree_size is always > 0")
    }

    pub fn leaf_count(&self) -> NonZeroUsize {
        let tree_size = self.total_node_count();
        tree_size.leaf_count()
    }

    pub fn level_count(&self) -> NonZeroUsize {
        let tree_size = self.total_node_count();
        tree_size.level_count()
    }

    pub fn node_value_from_bottom(
        &self,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Option<H256> {
        let index_in_tree = NodePosition::from_position(
            self.tree.len().try_into().expect("Tree size is by design > 0"),
            level_from_bottom,
            index_in_level,
        )?
        .abs_index();

        Some(self.tree[index_in_tree])
    }

    pub fn node_from_bottom(
        &self,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Option<Node> {
        let absolute_index = NodePosition::from_position(
            self.tree.len().try_into().expect("Tree size is by design > 0"),
            level_from_bottom,
            index_in_level,
        )?
        .abs_index();

        Some(Node {
            tree_ref: self,
            absolute_index,
        })
    }

    pub fn iter_from_leaf_to_root(
        &self,
        leaf_index: usize,
    ) -> Result<MerkleTreeNodeParentIterator, MerkleTreeAccessError> {
        let leaf_count = self.leaf_count().get();

        if leaf_index >= leaf_count {
            return Err(MerkleTreeAccessError::IterStartIndexOutOfRange(
                leaf_index, leaf_count,
            ));
        }

        let res = MerkleTreeNodeParentIterator {
            node: Some(Node {
                tree_ref: self,
                absolute_index: leaf_index,
            }),
        };

        Ok(res)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Node<'a> {
    tree_ref: &'a MerkleTree,
    absolute_index: usize,
}

impl<'a> Node<'a> {
    pub fn hash(&self) -> &H256 {
        &self.tree_ref.tree[self.absolute_index]
    }

    pub fn tree(&self) -> &'a MerkleTree {
        self.tree_ref
    }

    pub fn into_position(self) -> NodePosition {
        NodePosition::from_abs_index(self.tree().total_node_count(), self.absolute_index)
            .expect("Should never fail since the index is transitively valid")
    }

    pub fn abs_index(&self) -> usize {
        self.absolute_index
    }

    pub fn parent(&self) -> Option<Node<'a>> {
        let pos = self.into_position().parent()?;

        Some(Node {
            tree_ref: self.tree_ref,
            absolute_index: pos.abs_index(),
        })
    }

    /// Return the node that combines with this node to create a hash at the parent level.
    /// The idea is simply: If it's even, then the odd next to it is the one.
    ///                     If it's odd, then the even before it is the one.
    /// This can only be None for the root node.
    pub fn sibling(&self) -> Option<Node<'a>> {
        let absolute_index = self.into_position().sibling()?;
        Some(Node {
            tree_ref: self.tree_ref,
            absolute_index: absolute_index.abs_index(),
        })
    }

    pub fn is_root(&self) -> bool {
        self.absolute_index == self.tree().tree.len() - 1
    }

    pub fn into_iter_parents(self) -> MerkleTreeNodeParentIterator<'a> {
        MerkleTreeNodeParentIterator { node: Some(self) }
    }
}

/// An iterator that iterates from a leaf node to the root node.
#[must_use]
#[derive(Debug)]
pub struct MerkleTreeNodeParentIterator<'a> {
    node: Option<Node<'a>>,
}

impl<'a> Iterator for MerkleTreeNodeParentIterator<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        match self.node {
            None => None,
            Some(_) => {
                let res = self.node;
                self.node = self.node.as_ref()?.parent();
                res
            }
        }
    }
}

#[cfg(test)]
mod tests;

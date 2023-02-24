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

pub mod tree_size;

use std::num::NonZeroUsize;

use crypto::hash::StreamHasher;

use crate::primitives::{
    id::{default_hash, DefaultHashAlgoStream},
    H256,
};

use self::tree_size::TreeSize;

use super::{pos::NodePosition, MerkleTreeAccessError, MerkleTreeFormError};

pub enum AdjacentLeavesIndices {
    Alone(usize),
    Together(usize, usize),
}

/// Merkle tree in the form of a vector, where the bottom leaves are the based, and the root is
/// the last element.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MerkleTree {
    tree: Vec<H256>,
}

impl MerkleTree {
    fn create_merkletree_padding(elements: &[H256]) -> Vec<H256> {
        let orig_size = elements.len();
        let pow2_size = orig_size.next_power_of_two();

        assert!(pow2_size >= orig_size);

        let mut padding = Vec::with_capacity(pow2_size - orig_size);
        for _idx in orig_size..pow2_size {
            let to_hash = padding
                .last()
                .unwrap_or_else(|| elements.last().expect("We already checked it's not empty"));
            let to_push = default_hash(to_hash);
            padding.push(to_push);
        }
        padding
    }

    pub(crate) fn combine_pair(left: &H256, right: &H256) -> H256 {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(left.as_bytes());
        hasher.write(right.as_bytes());
        H256::from(hasher.finalize())
    }

    /// Create a new merkle tree from a list of leaves, and padding with incremental padding if needed.
    /// Incremental padding means that the padding is created by hashing the last element of the list,
    /// and then hashing the result with the next element of the list, and so on.
    pub fn from_leaves(leaves: Vec<H256>) -> Result<Self, MerkleTreeFormError> {
        if leaves.is_empty() {
            return Err(MerkleTreeFormError::TooSmall(leaves.len()));
        }
        let padding = Self::create_merkletree_padding(&leaves);
        let leaves = leaves.into_iter().chain(padding).collect::<Vec<_>>();
        let steps = leaves.len() - 1;
        let mut tree = Vec::with_capacity(2 * leaves.len() - 1);
        tree.extend(leaves.into_iter());
        for i in 0..steps {
            let el = Self::combine_pair(&tree[i * 2], &tree[i * 2 + 1]);
            tree.push(el);
        }
        TreeSize::from_value(tree.len()).expect("Invalid tree size. Invariant broken.");
        let res = Self { tree };
        Ok(res)
    }

    /// Get the root of the merkle tree.
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
        let tree_size = TreeSize::from_value(self.tree.len())
            .expect("(leaf_count) Tree size valid by construction");
        tree_size.leaf_count()
    }

    pub fn level_count(&self) -> NonZeroUsize {
        let tree_size = TreeSize::from_value(self.tree.len())
            .expect("(level_count) Tree size valid by construction");
        tree_size.level_count()
    }

    pub fn absolute_index_from_bottom(
        tree_size: TreeSize,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Option<usize> {
        let node = NodePosition::from_position(tree_size, level_from_bottom, index_in_level)?;

        Some(node.abs_index())
    }

    pub fn node_value_from_bottom(
        &self,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Option<H256> {
        let index_in_tree = Self::absolute_index_from_bottom(
            self.tree.len().try_into().expect("Tree size is by design > 0"),
            level_from_bottom,
            index_in_level,
        )?;

        Some(self.tree[index_in_tree])
    }

    pub fn node_from_bottom(
        &self,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Option<Node> {
        let absolute_index = Self::absolute_index_from_bottom(
            self.tree.len().try_into().expect("Tree size is by design > 0"),
            level_from_bottom,
            index_in_level,
        )?;

        Some(Node {
            tree_ref: self,
            absolute_index,
        })
    }

    /// Given an absolute index in the flattened tree, return the level and index at that level in the form (level, index_at_level)
    pub fn position_from_index(tree_size: TreeSize, absolute_index: usize) -> Option<NodePosition> {
        NodePosition::from_abs_index(tree_size, absolute_index)
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
        let pos = self.into_position();
        let (level, index) = pos.position();
        if level == self.tree().level_count().get() - 1 {
            return None;
        }

        let parent_level = level + 1;
        let parent_node_index_in_level = index / 2;

        let parent_absolute_index = MerkleTree::absolute_index_from_bottom(
            self.tree().total_node_count(),
            parent_level,
            parent_node_index_in_level,
        )
        .expect("Parent index must be in range");

        Some(Node {
            tree_ref: self.tree_ref,
            absolute_index: parent_absolute_index,
        })
    }

    /// Return the node that combines with this node to create a hash at the parent level.
    /// The idea is simply: If it's even, then the odd next to it is the one.
    ///                     If it's odd, then the even before it is the one.
    /// This can only be None for the root node.
    pub fn sibling(&self) -> Option<Node<'a>> {
        if self.absolute_index == self.tree().tree.len() - 1 {
            return None;
        }

        if self.absolute_index % 2 == 0 {
            Some(Node {
                tree_ref: self.tree_ref,
                absolute_index: self.absolute_index + 1,
            })
        } else {
            Some(Node {
                tree_ref: self.tree_ref,
                absolute_index: self.absolute_index - 1,
            })
        }
    }

    pub fn is_root(&self) -> bool {
        self.absolute_index == self.tree().tree.len() - 1
    }
}

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

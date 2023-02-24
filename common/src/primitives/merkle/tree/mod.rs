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

use super::{
    proof::single::SingleProofNodes, MerkleTreeAccessError, MerkleTreeFormError,
    MerkleTreeProofExtractionError,
};

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

    /// Create a new merkle tree from a list of leaves.
    pub fn from_leaves(leaves: Vec<H256>) -> Result<Self, MerkleTreeFormError> {
        // TODO: separate padding from this function and create a type that includes padding
        //       on creation by taking Vec<H256> as input and padding it and wrapping it with a strong type
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

    pub fn leaves_count(&self) -> NonZeroUsize {
        let tree_size = TreeSize::from_value(self.tree.len())
            .expect("(leaves_count) Tree size valid by construction");
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
    ) -> Result<usize, MerkleTreeAccessError> {
        let level_count = tree_size.level_count().get();
        if level_from_bottom >= level_count {
            return Err(MerkleTreeAccessError::LevelOutOfRange(
                tree_size.get(),
                level_from_bottom,
                index_in_level,
            ));
        }

        // To help in seeing how these formulas were derived, see this table that represents values in the case tree.len() == 31 == 0b11111:
        //  level     level_start  level_start in binary    index_in_level_size
        //  0         0            00000                    16
        //  1         16           10000                    8
        //  2         24           11000                    4
        //  3         28           11100                    2
        //  4         30           11110                    1

        let level_from_top = level_count - level_from_bottom;
        // to get leading ones, we shift the tree size, right then left, by the level we need (see the table above)
        let level_start = (tree_size.get() >> level_from_top) << level_from_top;
        let index_in_tree = level_start + index_in_level;
        // max number of nodes in a level, in level_from_bottom
        let index_in_level_size = if level_start > 0 {
            1 << (level_start.trailing_zeros() - 1)
        } else {
            tree_size.leaf_count().get()
        };
        if index_in_level >= index_in_level_size {
            return Err(MerkleTreeAccessError::IndexOutOfRange(
                tree_size.get(),
                level_from_bottom,
                index_in_level,
            ));
        }

        Ok(index_in_tree)
    }

    pub fn node_value_from_bottom(
        &self,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Result<H256, MerkleTreeAccessError> {
        let index_in_tree = Self::absolute_index_from_bottom(
            self.tree.len().try_into().expect("Tree size is by design > 0"),
            level_from_bottom,
            index_in_level,
        )?;

        Ok(self.tree[index_in_tree])
    }

    pub fn node_from_bottom(
        &self,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Result<Node, MerkleTreeAccessError> {
        let index_in_tree = Self::absolute_index_from_bottom(
            self.tree.len().try_into().expect("Tree size is by design > 0"),
            level_from_bottom,
            index_in_level,
        )?;

        Ok(Node {
            tree_ref: self,
            absolute_index: index_in_tree,
        })
    }

    /// Given an index in the flattened tree, return the level and index at that level in the form (level, index_at_level)
    pub fn position_from_index(tree_size: TreeSize, index: usize) -> (usize, usize) {
        assert_eq!(
            (tree_size.get() + 1).count_ones(),
            1,
            "A valid tree size is always a power of 2 minus one"
        );
        assert!(
            index < tree_size.get(),
            "Index must be within the tree size"
        );

        let leaves_count = tree_size.leaf_count();

        let mut level = 0;
        let mut nodes_at_level_count = leaves_count.get();
        let mut tree_node_counter = 0;
        while tree_node_counter + nodes_at_level_count <= index {
            level += 1;
            tree_node_counter += nodes_at_level_count;
            nodes_at_level_count >>= 1;
        }
        (level, index - tree_node_counter)
    }

    pub fn iter_from_leaf_to_root(
        &self,
        leaf_index: usize,
    ) -> Result<MerkleTreeNodeParentIterator, MerkleTreeAccessError> {
        let leaves_count = self.leaves_count().get();

        if leaf_index >= leaves_count {
            return Err(MerkleTreeAccessError::IterStartIndexOutOfRange(
                leaf_index,
                leaves_count,
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

    /// See SingleProofNodes::from_tree_leaf
    pub fn proof_from_leaf(
        &self,
        leaf_index: usize,
    ) -> Result<SingleProofNodes, MerkleTreeProofExtractionError> {
        SingleProofNodes::from_tree_leaf(self, leaf_index)
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

    pub fn position(&self) -> (usize, usize) {
        let tree_size = TreeSize::from_value(self.tree_ref.tree.len())
            .expect("By design, tree_size is always valid");
        MerkleTree::position_from_index(tree_size, self.absolute_index)
    }

    pub fn abs_index(&self) -> usize {
        self.absolute_index
    }

    pub fn parent(&self) -> Option<Node<'a>> {
        let (level, index) = self.position();
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

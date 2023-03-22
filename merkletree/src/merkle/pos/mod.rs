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

pub mod node_kind;

use std::num::NonZeroUsize;

use self::node_kind::NodeKind;

use super::tree::tree_size::TreeSize;

/// Given a binary tree with leaf-count as powers of 2, this struct represents a position in the tree.
/// This also contains all the math required to convert position representations.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodePosition {
    tree_size: TreeSize,
    absolute_index: usize,
}

impl NodePosition {
    pub fn from_abs_index(tree_size: TreeSize, absolute_index: usize) -> Option<Self> {
        if absolute_index >= tree_size.get() {
            return None;
        }

        Some(Self {
            tree_size,
            absolute_index,
        })
    }

    pub fn from_position(
        tree_size: TreeSize,
        level_from_bottom: usize,
        index_in_level: usize,
    ) -> Option<Self> {
        let level_count = tree_size.level_count().get();
        if level_from_bottom >= level_count {
            return None;
        }

        let level_start = tree_size.level_start(level_from_bottom)?;
        let absolute_index = level_start + index_in_level;
        let level_from_top = level_count - level_from_bottom - 1;

        // number of nodes in the level
        let index_in_level_size = 1 << level_from_top;

        if index_in_level >= index_in_level_size {
            return None;
        }

        Some(Self {
            tree_size,
            absolute_index,
        })
    }

    pub fn tree_size(&self) -> TreeSize {
        self.tree_size
    }

    pub fn abs_index(&self) -> usize {
        self.absolute_index
    }

    /// Returns the level and index in the level of the node, as in (level, index).
    /// Notice that the index value is capped by the number of nodes in the level.
    pub fn position(&self) -> (usize, usize) {
        assert!(
            self.abs_index() < self.tree_size.get(),
            "Index must be within the tree size"
        );

        let level_from_top = (self.tree_size.get() - self.abs_index() + 1)
            .next_power_of_two()
            .trailing_zeros() as usize;

        let level = self.tree_size.level_count().get() - level_from_top;
        let level_start = self.tree_size.level_start(level).expect("Abs index is valid");
        assert!(level_start <= self.abs_index());
        (level, self.abs_index() - level_start)
    }

    pub fn node_kind(&self) -> NodeKind {
        if self.abs_index() == self.tree_size.get() - 1 {
            return NodeKind::Root;
        }

        if self.abs_index() % 2 == 0 {
            NodeKind::LeftChild
        } else {
            NodeKind::RightChild
        }
    }

    pub fn tree_level_count(&self) -> NonZeroUsize {
        (self.tree_size.get().trailing_ones() as usize)
            .try_into()
            .expect("Cannot be zero if tree_size is not zero")
    }

    pub fn parent(&self) -> Option<Self> {
        let (level, index) = self.position();
        if level == self.tree_level_count().get() - 1 {
            return None;
        }

        let parent_level = level + 1;
        let parent_node_index_in_level = index / 2;

        let parent_position =
            NodePosition::from_position(self.tree_size, parent_level, parent_node_index_in_level)
                .expect("Parent index must be in range");

        Some(Self {
            tree_size: self.tree_size,
            absolute_index: parent_position.abs_index(),
        })
    }

    pub fn sibling(&self) -> Option<Self> {
        if self.node_kind().is_root() {
            return None;
        }

        // We use xor to get the sibling index because the sibling is always the opposite bit.
        // Practically we add one to the absolute index to get the sibling if it's a left, and subtract one if it's a right.
        let absolute_index = self.absolute_index ^ 1;

        Some(Self {
            tree_size: self.tree_size,
            absolute_index,
        })
    }

    pub fn into_iter_parents(self) -> MerkleTreeNodePositionParentIterator {
        MerkleTreeNodePositionParentIterator { node: Some(self) }
    }
}

/// An iterator over the parents of a node, given its position.
#[must_use]
#[derive(Debug)]
pub struct MerkleTreeNodePositionParentIterator {
    node: Option<NodePosition>,
}

impl Iterator for MerkleTreeNodePositionParentIterator {
    type Item = NodePosition;

    fn next(&mut self) -> Option<NodePosition> {
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

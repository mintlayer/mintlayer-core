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

use std::num::NonZeroUsize;

use super::tree::MerkleTree;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodePosition {
    tree_size: NonZeroUsize,
    absolute_index: usize,
}

impl NodePosition {
    // TODO(PR): test all these constructors
    // TODO(PR): See whether we wanna create a TreeSize type that can be created from both leaf count or total node count
    pub fn from_abs_index(tree_size: NonZeroUsize, absolute_index: usize) -> Option<Self> {
        if (tree_size.get() + 1).count_ones() != 1 {
            return None;
        }

        Some(Self {
            tree_size,
            absolute_index,
        })
    }

    pub fn from_position(tree_size: NonZeroUsize, level: usize, index: usize) -> Option<Self> {
        let absolute_index =
            MerkleTree::absolute_index_from_bottom(tree_size, level, index).ok()?;
        Some(Self {
            tree_size,
            absolute_index,
        })
    }

    pub fn tree_size(&self) -> NonZeroUsize {
        self.tree_size
    }

    pub fn abs_index(&self) -> usize {
        self.absolute_index
    }

    pub fn position(&self) -> (usize, usize) {
        MerkleTree::position_from_index(self.tree_size, self.absolute_index)
    }

    pub fn tree_level_count(&self) -> NonZeroUsize {
        assert_eq!(
            (self.tree_size.get() + 1).count_ones(),
            1,
            "A valid tree size is always a power of 2 minus one"
        );
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

        let parent_absolute_index = MerkleTree::absolute_index_from_bottom(
            self.tree_size,
            parent_level,
            parent_node_index_in_level,
        )
        .expect("Parent index must be in range");

        Some(Self {
            tree_size: self.tree_size,
            absolute_index: parent_absolute_index,
        })
    }

    pub fn sibling(&self) -> Option<Self> {
        if self.absolute_index == self.tree_size.get() - 1 {
            return None;
        }

        if self.absolute_index % 2 == 0 {
            Some(Self {
                tree_size: self.tree_size,
                absolute_index: self.absolute_index + 1,
            })
        } else {
            Some(Self {
                tree_size: self.tree_size,
                absolute_index: self.absolute_index - 1,
            })
        }
    }

    pub fn iter_parents(&self) -> MerkleTreeNodePositionParentIterator {
        MerkleTreeNodePositionParentIterator { node: Some(*self) }
    }
}

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

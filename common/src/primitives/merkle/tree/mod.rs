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

use crypto::hash::StreamHasher;

use crate::primitives::{
    id::{default_hash, DefaultHashAlgoStream},
    H256,
};

use super::{MerkleTreeAccessError, MerkleTreeFormError};

pub enum AdjacentLeavesIndices {
    Alone(usize),
    Together(usize, usize),
}

/// Merkle tree in the form of a vector, where the bottom leaves are the based, and the root is
/// the last element.
#[derive(Debug)]
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

    fn combine_pair(left: &H256, right: &H256) -> H256 {
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
        let res = Self { tree };
        Ok(res)
    }

    /// Get the root of the merkle tree.
    pub fn root(&self) -> H256 {
        *self.tree.last().expect("By design, at least one element must exist")
    }

    fn leaves_count_from_tree_size(tree_size: NonZeroUsize) -> NonZeroUsize {
        assert_eq!(
            (tree_size.get() + 1).count_ones(),
            1,
            "A valid tree size is always a power of 2 minus one"
        );

        let tree_size = tree_size.get();
        let leaves_count = (tree_size + 1) >> 1;
        debug_assert!(leaves_count.is_power_of_two());
        NonZeroUsize::new(leaves_count).expect("By design, tree_size is always > 0")
    }

    pub fn level_count(&self) -> usize {
        let leaves_count = Self::leaves_count_from_tree_size(
            NonZeroUsize::new(self.tree.len()).expect("By design, tree_size is always > 0"),
        );

        leaves_count.trailing_zeros() as usize + 1
    }

    pub fn node_from_bottom(
        &self,
        level_from_bottom: usize,
        index: usize,
    ) -> Result<H256, MerkleTreeAccessError> {
        let level_count = self.level_count();
        if level_from_bottom >= level_count {
            return Err(MerkleTreeAccessError::LevelOutOfRange(
                self.tree.len(),
                level_from_bottom,
                index,
            ));
        }
        let level_from_top = level_count - level_from_bottom;
        let level_start = (self.tree.len() >> level_from_top) << level_from_top;
        let index = level_start + index;
        // TODO(PR): check index access
        let index_size = usize::MAX;
        if index >= index_size {
            return Err(MerkleTreeAccessError::IndexOutOfRange(
                self.tree.len(),
                level_from_bottom,
                index,
            ));
        }

        Ok(self.tree[index])
    }

    /// Given an index in the flattened tree, return the level and index at that level in the form (level, index_at_level)
    pub fn position_from_index(tree_size: NonZeroUsize, index: usize) -> (usize, usize) {
        assert_eq!(
            (tree_size.get() + 1).count_ones(),
            1,
            "A valid tree size is always a power of 2 minus one"
        );
        assert!(
            index < tree_size.get(),
            "Index must be within the tree size"
        );

        let leaves_count = Self::leaves_count_from_tree_size(tree_size);

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
}

#[cfg(test)]
mod tests;

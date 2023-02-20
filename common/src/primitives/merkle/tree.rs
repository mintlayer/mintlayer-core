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
use itertools::Itertools;

use crate::primitives::{
    id::{default_hash, DefaultHashAlgoStream},
    H256,
};

use super::{MerkleTreeAccessError, MerkleTreeFormError, MerkleTreeProofExtractionError};

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

/// Ensure the leaves indices are sorted and unique
fn is_sorted_and_unique(leaves_indices: &[u32]) -> bool {
    leaves_indices.iter().tuple_windows::<(&u32, &u32)>().all(|(i, j)| i < j)
}

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

impl MerkleTree {
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
        let padding = create_merkletree_padding(&leaves);
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

    /// Find adjacent leaves indices in a merkle tree
    fn get_adjacent_indices_states(
        leaves_indices: &[u32],
    ) -> Result<Vec<AdjacentLeavesIndices>, MerkleTreeProofExtractionError> {
        if !is_sorted_and_unique(leaves_indices) {
            return Err(
                MerkleTreeProofExtractionError::UnsortedOrUniqueLeavesIndices(
                    leaves_indices.to_vec(),
                ),
            );
        }

        let mut res = Vec::with_capacity(leaves_indices.len());

        // we chain the windows with a max value to ensure we get the last element if it doesn't pair with the preceding value
        let max_chain = std::iter::once(&u32::MAX);
        for win in leaves_indices.iter().chain(max_chain).tuple_windows::<(&u32, &u32)>() {
            let (a, b) = (*win.0, *win.1);

            // In a tree, we expect elements to be adjacent if the first one has even index and the second one has index + 1.
            if a % 2 == 0 && a + 1 == b {
                res.push(AdjacentLeavesIndices::Together(a as usize, b as usize));
            } else {
                res.push(AdjacentLeavesIndices::Alone(a as usize));
            }
        }

        Ok(res)
    }

    pub fn level_count(&self) -> usize {
        let leaves_count = Self::leaves_count_from_tree_size(
            NonZeroUsize::new(self.tree.len()).expect("By design, tree_size is always > 0"),
        );

        let level_count = leaves_count.trailing_zeros() as usize + 1;

        level_count
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

    /// Multi-proof of inclusion for a list of elements
    pub fn multi_proof(
        &self,
        leaves_indices: &[u32],
    ) -> Result<Vec<H256>, MerkleTreeProofExtractionError> {
        let leaves_count = Self::leaves_count_from_tree_size(
            NonZeroUsize::new(self.tree.len()).expect("By design, tree_size is always > 0"),
        );

        if leaves_indices.iter().any(|v| *v > leaves_count.get() as u32) {
            return Err(MerkleTreeProofExtractionError::IndexOutOfRange(
                leaves_indices.to_vec(),
                leaves_count.get(),
            ));
        }

        let _adjacent_states = Self::get_adjacent_indices_states(leaves_indices)?;
        // TODO(PR): finish the implementation

        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::id::{default_hash, DefaultHashAlgoStream};
    use crypto::hash::StreamHasher;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Rng, Seed};

    #[test]
    fn merkletree_too_small() {
        let t0 = MerkleTree::from_leaves(vec![]);
        assert_eq!(t0.unwrap_err(), MerkleTreeFormError::TooSmall(0));
    }

    #[test]
    fn merkletree_basic_two_leaf_node() {
        let v1 = default_hash(H256::zero());
        let v2 = default_hash(H256::from_low_u64_be(1));

        let t = MerkleTree::from_leaves(vec![v1, v2]).unwrap();

        // recreate the expected root
        let mut test_hasher = DefaultHashAlgoStream::new();
        test_hasher.write(v1);
        test_hasher.write(v2);

        assert_eq!(t.root(), test_hasher.finalize().into());
    }

    #[test]
    fn merkletree_basic_four_leaf_node() {
        let v1 = default_hash(H256::zero());
        let v2 = default_hash(H256::from_low_u64_be(1));
        let v3 = default_hash(H256::from_low_u64_be(2));
        let v4 = default_hash(H256::from_low_u64_be(3));

        let t = MerkleTree::from_leaves(vec![v1, v2, v3, v4]).unwrap();

        // recreate the expected root
        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(v1);
        node10.write(v2);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(v3);
        node11.write(v4);

        let mut node00 = DefaultHashAlgoStream::new();
        let n10 = node10.finalize();
        node00.write(n10);
        let n11 = node11.finalize();
        node00.write(n11);

        let res = node00.finalize();

        assert_eq!(t.root(), res.into());
    }

    #[test]
    fn merkletree_basic_eight_leaf_node() {
        let v1 = default_hash(H256::zero());
        let v2 = default_hash(H256::from_low_u64_be(1));
        let v3 = default_hash(H256::from_low_u64_be(2));
        let v4 = default_hash(H256::from_low_u64_be(3));
        let v5 = default_hash(H256::from_low_u64_be(4));
        let v6 = default_hash(H256::from_low_u64_be(5));
        let v7 = default_hash(H256::from_low_u64_be(6));
        let v8 = default_hash(H256::from_low_u64_be(7));

        let t = MerkleTree::from_leaves(vec![v1, v2, v3, v4, v5, v6, v7, v8]).unwrap();

        // recreate the expected root
        let mut node20 = DefaultHashAlgoStream::new();
        node20.write(v1);
        node20.write(v2);

        let mut node21 = DefaultHashAlgoStream::new();
        node21.write(v3);
        node21.write(v4);

        let mut node22 = DefaultHashAlgoStream::new();
        node22.write(v5);
        node22.write(v6);

        let mut node23 = DefaultHashAlgoStream::new();
        node23.write(v7);
        node23.write(v8);

        let n20 = node20.finalize();
        let n21 = node21.finalize();
        let n22 = node22.finalize();
        let n23 = node23.finalize();

        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(n20);
        node10.write(n21);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(n22);
        node11.write(n23);

        let n10 = node10.finalize();
        let n11 = node11.finalize();

        let mut node00 = DefaultHashAlgoStream::new();
        node00.write(H256::from(n10));
        node00.write(H256::from(n11));

        let res = node00.finalize();

        assert_eq!(t.root(), H256::from(res));
    }

    #[test]
    fn merkletree_with_arbitrary_length_2() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);

        let t = MerkleTree::from_leaves(vec![v1, v2]).unwrap();

        // recreate the expected root
        let mut test_hasher = DefaultHashAlgoStream::new();
        test_hasher.write(v1);
        test_hasher.write(v2);

        assert_eq!(t.root(), test_hasher.finalize().into());
    }

    #[test]
    fn merkletree_with_arbitrary_length_3() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);
        let v3 = H256::from_low_u64_be(2);

        let t = MerkleTree::from_leaves(vec![v1, v2, v3]).unwrap();

        // recreate the expected root
        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(v1);
        node10.write(v2);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(v3);
        node11.write(default_hash(v3));

        let mut node00 = DefaultHashAlgoStream::new();
        let n10 = node10.finalize();
        node00.write(n10);
        let n11 = node11.finalize();
        node00.write(n11);

        let res = node00.finalize();

        assert_eq!(t.root(), res.into());
    }

    #[test]
    fn merkletree_with_arbitrary_length_5() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);
        let v3 = H256::from_low_u64_be(2);
        let v4 = H256::from_low_u64_be(3);
        let v5 = H256::from_low_u64_be(4);
        let v6 = default_hash(v5);
        let v7 = default_hash(v6);
        let v8 = default_hash(v7);

        let t = MerkleTree::from_leaves(vec![v1, v2, v3, v4, v5]).unwrap();

        // recreate the expected root
        let mut node20 = DefaultHashAlgoStream::new();
        node20.write(v1);
        node20.write(v2);

        let mut node21 = DefaultHashAlgoStream::new();
        node21.write(v3);
        node21.write(v4);

        let mut node22 = DefaultHashAlgoStream::new();
        node22.write(v5);
        node22.write(v6);

        let mut node23 = DefaultHashAlgoStream::new();
        node23.write(v7);
        node23.write(v8);

        let n20 = node20.finalize();
        let n21 = node21.finalize();
        let n22 = node22.finalize();
        let n23 = node23.finalize();

        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(n20);
        node10.write(n21);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(n22);
        node11.write(n23);

        let n10 = node10.finalize();
        let n11 = node11.finalize();

        let mut node00 = DefaultHashAlgoStream::new();
        node00.write(n10);
        node00.write(n11);

        let res = node00.finalize();

        assert_eq!(t.root(), res.into());
    }

    #[test]
    fn leaves_count_from_tree_size() {
        for i in 1..30 {
            let leaves_count = 1 << (i - 1);
            let tree_size = (1 << i) - 1;
            assert_eq!(
                MerkleTree::leaves_count_from_tree_size(tree_size.try_into().unwrap()),
                NonZeroUsize::new(leaves_count).unwrap(),
                "Check failed for i = {}",
                i
            );
        }
    }

    #[rstest]
    #[should_panic(expected = "A valid tree size is always a power of 2 minus one")]
    #[case(Seed::from_entropy())]
    fn leaves_count_from_tree_size_error(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut i = rng.gen::<usize>();
        while (i + 1usize).count_ones() == 1 {
            i = rng.gen::<usize>();
        }
        let _leaves_count = MerkleTree::leaves_count_from_tree_size(i.try_into().unwrap());
    }

    #[test]
    fn bottom_access_one_leaf() {
        let v00 = H256::from_low_u64_be(1);

        let t = MerkleTree::from_leaves(vec![v00]).unwrap();

        assert_eq!(t.node_from_bottom(0, 0).unwrap(), v00);
    }

    #[test]
    fn bottom_access_two_leaves() {
        let v00 = H256::zero();
        let v01 = H256::from_low_u64_be(1);

        let t = MerkleTree::from_leaves(vec![v00, v01]).unwrap();

        assert_eq!(t.node_from_bottom(0, 0).unwrap(), v00);
        assert_eq!(t.node_from_bottom(0, 1).unwrap(), v01);

        let v10 = MerkleTree::combine_pair(&v00, &v01);

        assert_eq!(t.node_from_bottom(1, 0).unwrap(), v10);
    }

    #[test]
    fn bottom_access_four_leaves() {
        let v00 = H256::zero();
        let v01 = H256::from_low_u64_be(1);
        let v02 = H256::from_low_u64_be(2);
        let v03 = H256::from_low_u64_be(3);

        let t = MerkleTree::from_leaves(vec![v00, v01, v02, v03]).unwrap();

        assert_eq!(t.node_from_bottom(0, 0).unwrap(), v00);
        assert_eq!(t.node_from_bottom(0, 1).unwrap(), v01);
        assert_eq!(t.node_from_bottom(0, 2).unwrap(), v02);
        assert_eq!(t.node_from_bottom(0, 3).unwrap(), v03);

        let v10 = MerkleTree::combine_pair(&v00, &v01);
        let v11 = MerkleTree::combine_pair(&v02, &v03);

        assert_eq!(t.node_from_bottom(1, 0).unwrap(), v10);
        assert_eq!(t.node_from_bottom(1, 1).unwrap(), v11);

        let v20 = MerkleTree::combine_pair(&v10, &v11);

        assert_eq!(t.node_from_bottom(2, 0).unwrap(), v20);
    }

    #[test]
    fn bottom_access_eight_leaves() {
        let v00 = H256::zero();
        let v01 = H256::from_low_u64_be(1);
        let v02 = H256::from_low_u64_be(2);
        let v03 = H256::from_low_u64_be(3);
        let v04 = H256::from_low_u64_be(4);
        let v05 = default_hash(v04);
        let v06 = default_hash(v05);
        let v07 = default_hash(v06);

        let t = MerkleTree::from_leaves(vec![v00, v01, v02, v03, v04]).unwrap();

        assert_eq!(t.node_from_bottom(0, 0).unwrap(), v00);
        assert_eq!(t.node_from_bottom(0, 1).unwrap(), v01);
        assert_eq!(t.node_from_bottom(0, 2).unwrap(), v02);
        assert_eq!(t.node_from_bottom(0, 3).unwrap(), v03);
        assert_eq!(t.node_from_bottom(0, 4).unwrap(), v04);
        assert_eq!(t.node_from_bottom(0, 5).unwrap(), v05);
        assert_eq!(t.node_from_bottom(0, 6).unwrap(), v06);
        assert_eq!(t.node_from_bottom(0, 7).unwrap(), v07);

        let v10 = MerkleTree::combine_pair(&v00, &v01);
        let v11 = MerkleTree::combine_pair(&v02, &v03);
        let v12 = MerkleTree::combine_pair(&v04, &v05);
        let v13 = MerkleTree::combine_pair(&v06, &v07);

        assert_eq!(t.node_from_bottom(1, 0).unwrap(), v10);
        assert_eq!(t.node_from_bottom(1, 1).unwrap(), v11);
        assert_eq!(t.node_from_bottom(1, 2).unwrap(), v12);
        assert_eq!(t.node_from_bottom(1, 3).unwrap(), v13);

        let v20 = MerkleTree::combine_pair(&v10, &v11);
        let v21 = MerkleTree::combine_pair(&v12, &v13);

        assert_eq!(t.node_from_bottom(2, 0).unwrap(), v20);
        assert_eq!(t.node_from_bottom(2, 1).unwrap(), v21);

        let v30 = MerkleTree::combine_pair(&v20, &v21);
        assert_eq!(t.node_from_bottom(3, 0).unwrap(), v30);
    }

    #[test]
    fn sorted_and_unique() {
        assert!(is_sorted_and_unique(&[]));
        assert!(is_sorted_and_unique(&[1]));
        assert!(is_sorted_and_unique(&[1, 2]));
        assert!(is_sorted_and_unique(&[1, 2, 5, 10]));
        assert!(is_sorted_and_unique(&[1, 2, 5, 10, 100]));

        assert!(!is_sorted_and_unique(&[1, 1]));
        assert!(!is_sorted_and_unique(&[2, 1]));
        assert!(!is_sorted_and_unique(&[1, 2, 5, 10, 100, 99]));
        assert!(!is_sorted_and_unique(&[2, 1, 2, 5, 10, 100]));
        assert!(!is_sorted_and_unique(&[1, 2, 5, 4, 10, 100]));
    }

    #[test]
    fn position_from_index_1_tree_element() {
        let tree_size: NonZeroUsize = 1.try_into().unwrap();
        {
            let level = 0;
            let level_start = 0;
            let level_end: usize = 1;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
    }

    #[test]
    fn position_from_index_3_tree_elements() {
        let tree_size: NonZeroUsize = 3.try_into().unwrap();
        {
            let level = 0;
            let level_start = 0;
            let level_end: usize = 2;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
        {
            let level = 1;
            let level_start = 2;
            let level_end: usize = 3;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
    }

    #[test]
    fn position_from_index_7_tree_elements() {
        let tree_size: NonZeroUsize = 7.try_into().unwrap();
        {
            let level = 0;
            let level_start = 0;
            let level_end: usize = 4;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
        {
            let level = 1;
            let level_start = 4;
            let level_end: usize = 6;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
        {
            let level = 2;
            let level_start = 6;
            let level_end: usize = 7;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
    }

    #[test]
    fn position_from_index_15_tree_elements() {
        let tree_size: NonZeroUsize = 15.try_into().unwrap();
        {
            let level = 0;
            let level_start = 0;
            let level_end: usize = 8;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
        {
            let level = 1;
            let level_start = 8;
            let level_end: usize = 12;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
        {
            let level = 2;
            let level_start = 12;
            let level_end: usize = 14;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
        {
            let level = 3;
            let level_start = 14;
            let level_end: usize = 15;
            for i in level_start..level_end {
                assert_eq!(
                    MerkleTree::position_from_index(tree_size, i),
                    (level, i - level_start)
                );
            }
        }
    }
}

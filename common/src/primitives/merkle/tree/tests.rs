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

    assert_eq!(t.node_value_from_bottom(0, 0).unwrap(), v00);

    // Some invalid accesses at index
    for idx in 1..100 {
        let level = 0;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(1, level, idx)
        );
    }

    // Some invalid accesses at level
    for idx in 0..100 {
        for level in 1..100 {
            assert_eq!(
                t.node_value_from_bottom(level, idx).unwrap_err(),
                MerkleTreeAccessError::LevelOutOfRange(1, level, idx)
            );
        }
    }
}

#[test]
fn bottom_access_two_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);

    let t = MerkleTree::from_leaves(vec![v00, v01]).unwrap();

    assert_eq!(t.node_value_from_bottom(0, 0).unwrap(), v00);
    assert_eq!(t.node_value_from_bottom(0, 1).unwrap(), v01);

    let v10 = MerkleTree::combine_pair(&v00, &v01);

    assert_eq!(t.node_value_from_bottom(1, 0).unwrap(), v10);

    // Some invalid accesses at index
    for idx in 2..100 {
        let level = 0;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(3, level, idx)
        );
    }

    for idx in 1..100 {
        let level = 1;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(3, level, idx)
        );
    }

    // Some invalid accesses at level
    for idx in 0..100 {
        for level in 2..100 {
            assert_eq!(
                t.node_value_from_bottom(level, idx).unwrap_err(),
                MerkleTreeAccessError::LevelOutOfRange(3, level, idx)
            );
        }
    }
}

#[test]
fn bottom_access_four_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);
    let v02 = H256::from_low_u64_be(2);
    let v03 = H256::from_low_u64_be(3);

    let t = MerkleTree::from_leaves(vec![v00, v01, v02, v03]).unwrap();

    assert_eq!(t.node_value_from_bottom(0, 0).unwrap(), v00);
    assert_eq!(t.node_value_from_bottom(0, 1).unwrap(), v01);
    assert_eq!(t.node_value_from_bottom(0, 2).unwrap(), v02);
    assert_eq!(t.node_value_from_bottom(0, 3).unwrap(), v03);

    let v10 = MerkleTree::combine_pair(&v00, &v01);
    let v11 = MerkleTree::combine_pair(&v02, &v03);

    assert_eq!(t.node_value_from_bottom(1, 0).unwrap(), v10);
    assert_eq!(t.node_value_from_bottom(1, 1).unwrap(), v11);

    let v20 = MerkleTree::combine_pair(&v10, &v11);

    assert_eq!(t.node_value_from_bottom(2, 0).unwrap(), v20);

    // Some invalid accesses at index
    for idx in 4..100 {
        let level = 0;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(7, level, idx)
        );
    }

    for idx in 2..100 {
        let level = 1;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(7, level, idx)
        );
    }

    for idx in 1..100 {
        let level = 2;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(7, level, idx)
        );
    }

    // Some invalid accesses at level
    for idx in 0..100 {
        for level in 3..100 {
            assert_eq!(
                t.node_value_from_bottom(level, idx).unwrap_err(),
                MerkleTreeAccessError::LevelOutOfRange(7, level, idx)
            );
        }
    }
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

    assert_eq!(t.node_value_from_bottom(0, 0).unwrap(), v00);
    assert_eq!(t.node_value_from_bottom(0, 1).unwrap(), v01);
    assert_eq!(t.node_value_from_bottom(0, 2).unwrap(), v02);
    assert_eq!(t.node_value_from_bottom(0, 3).unwrap(), v03);
    assert_eq!(t.node_value_from_bottom(0, 4).unwrap(), v04);
    assert_eq!(t.node_value_from_bottom(0, 5).unwrap(), v05);
    assert_eq!(t.node_value_from_bottom(0, 6).unwrap(), v06);
    assert_eq!(t.node_value_from_bottom(0, 7).unwrap(), v07);

    let v10 = MerkleTree::combine_pair(&v00, &v01);
    let v11 = MerkleTree::combine_pair(&v02, &v03);
    let v12 = MerkleTree::combine_pair(&v04, &v05);
    let v13 = MerkleTree::combine_pair(&v06, &v07);

    assert_eq!(t.node_value_from_bottom(1, 0).unwrap(), v10);
    assert_eq!(t.node_value_from_bottom(1, 1).unwrap(), v11);
    assert_eq!(t.node_value_from_bottom(1, 2).unwrap(), v12);
    assert_eq!(t.node_value_from_bottom(1, 3).unwrap(), v13);

    let v20 = MerkleTree::combine_pair(&v10, &v11);
    let v21 = MerkleTree::combine_pair(&v12, &v13);

    assert_eq!(t.node_value_from_bottom(2, 0).unwrap(), v20);
    assert_eq!(t.node_value_from_bottom(2, 1).unwrap(), v21);

    let v30 = MerkleTree::combine_pair(&v20, &v21);
    assert_eq!(t.node_value_from_bottom(3, 0).unwrap(), v30);

    // Some invalid accesses at index
    for idx in 8..100 {
        let level = 0;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(15, level, idx)
        );
    }

    for idx in 4..100 {
        let level = 1;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(15, level, idx)
        );
    }

    for idx in 2..100 {
        let level = 2;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(15, level, idx)
        );
    }

    for idx in 1..100 {
        let level = 3;
        assert_eq!(
            t.node_value_from_bottom(level, idx).unwrap_err(),
            MerkleTreeAccessError::IndexOutOfRange(15, level, idx)
        );
    }

    // Some invalid accesses at level
    for idx in 0..100 {
        for level in 4..100 {
            assert_eq!(
                t.node_value_from_bottom(level, idx).unwrap_err(),
                MerkleTreeAccessError::LevelOutOfRange(15, level, idx)
            );
        }
    }
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

#[test]
fn absolute_index_from_bottom() {
    // Tree size: 1
    let s: NonZeroUsize = 1.try_into().expect("is not zero");
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 0).unwrap(), 0);

    // Tree size: 3
    let s: NonZeroUsize = 3.try_into().expect("is not zero");
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 0).unwrap(), 0);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 1).unwrap(), 1);

    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 1, 0).unwrap(), 2);

    // Tree size: 7
    let s: NonZeroUsize = 7.try_into().expect("is not zero");
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 0).unwrap(), 0);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 1).unwrap(), 1);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 2).unwrap(), 2);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 3).unwrap(), 3);

    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 1, 0).unwrap(), 4);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 1, 1).unwrap(), 5);

    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 2, 0).unwrap(), 6);

    // Tree size: 15
    let s: NonZeroUsize = 15.try_into().expect("is not zero");
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 0).unwrap(), 0);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 1).unwrap(), 1);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 2).unwrap(), 2);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 3).unwrap(), 3);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 4).unwrap(), 4);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 5).unwrap(), 5);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 6).unwrap(), 6);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 0, 7).unwrap(), 7);

    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 1, 0).unwrap(), 8);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 1, 1).unwrap(), 9);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 1, 2).unwrap(), 10);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 1, 3).unwrap(), 11);

    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 2, 0).unwrap(), 12);
    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 2, 1).unwrap(), 13);

    assert_eq!(MerkleTree::absolute_index_from_bottom(s, 3, 0).unwrap(), 14);
}

#[test]
fn parent_iter_one_leaf() {
    let v00 = H256::from_low_u64_be(1);

    let t = MerkleTree::from_leaves(vec![v00]).unwrap();

    let val = |v: Node| *v.hash();

    let mut leaf0iter = t.iter_from_leaf_to_root(0).unwrap();
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(0, 0).ok()
    );
    assert_eq!(leaf0iter.next().map(val), None);

    // Error cases: Invalid access
    for i in t.leaves_count().get()..100 {
        assert_eq!(
            t.iter_from_leaf_to_root(i).unwrap_err(),
            MerkleTreeAccessError::IterStartIndexOutOfRange(i, t.leaves_count().get())
        );
    }
}

#[test]
fn parent_iter_two_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);

    let t = MerkleTree::from_leaves(vec![v00, v01]).unwrap();

    let val = |v: Node| *v.hash();

    let mut leaf0iter = t.iter_from_leaf_to_root(0).unwrap();
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(0, 0).ok()
    );
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(1, 0).ok()
    );
    assert_eq!(leaf0iter.next().map(val), None);

    let mut leaf1iter = t.iter_from_leaf_to_root(1).unwrap();
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(0, 1).ok()
    );
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(1, 0).ok()
    );
    assert_eq!(leaf1iter.next().map(val), None);

    // Error cases: Invalid access
    for i in t.leaves_count().get()..100 {
        assert_eq!(
            t.iter_from_leaf_to_root(i).unwrap_err(),
            MerkleTreeAccessError::IterStartIndexOutOfRange(i, t.leaves_count().get())
        );
    }
}

#[test]
fn parent_iter_four_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);
    let v02 = H256::from_low_u64_be(2);
    let v03 = H256::from_low_u64_be(3);

    let t = MerkleTree::from_leaves(vec![v00, v01, v02, v03]).unwrap();

    let val = |v: Node| *v.hash();

    let mut leaf0iter = t.iter_from_leaf_to_root(0).unwrap();
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(0, 0).ok()
    );
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(1, 0).ok()
    );
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(leaf0iter.next().map(val), None);

    let mut leaf1iter = t.iter_from_leaf_to_root(1).unwrap();
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(0, 1).ok()
    );
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(1, 0).ok()
    );
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(leaf1iter.next().map(val), None);

    let mut leaf2iter = t.iter_from_leaf_to_root(2).unwrap();
    assert_eq!(
        leaf2iter.next().map(val),
        t.node_value_from_bottom(0, 2).ok()
    );
    assert_eq!(
        leaf2iter.next().map(val),
        t.node_value_from_bottom(1, 1).ok()
    );
    assert_eq!(
        leaf2iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(leaf2iter.next().map(val), None);

    let mut leaf3iter = t.iter_from_leaf_to_root(3).unwrap();
    assert_eq!(
        leaf3iter.next().map(val),
        t.node_value_from_bottom(0, 3).ok()
    );
    assert_eq!(
        leaf3iter.next().map(val),
        t.node_value_from_bottom(1, 1).ok()
    );
    assert_eq!(
        leaf3iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(leaf3iter.next().map(val), None);

    // Error cases: Invalid access
    for i in t.leaves_count().get()..100 {
        assert_eq!(
            t.iter_from_leaf_to_root(i).unwrap_err(),
            MerkleTreeAccessError::IterStartIndexOutOfRange(i, t.leaves_count().get())
        );
    }
}

#[test]
fn parent_iter_eight_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);
    let v02 = H256::from_low_u64_be(2);
    let v03 = H256::from_low_u64_be(3);
    let v04 = H256::from_low_u64_be(4);

    let t = MerkleTree::from_leaves(vec![v00, v01, v02, v03, v04]).unwrap();

    let val = |v: Node| *v.hash();

    let mut leaf0iter = t.iter_from_leaf_to_root(0).unwrap();
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(0, 0).ok()
    );
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(1, 0).ok()
    );
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(
        leaf0iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf0iter.next().map(val), None);

    let mut leaf1iter = t.iter_from_leaf_to_root(1).unwrap();
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(0, 1).ok()
    );
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(1, 0).ok()
    );
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(
        leaf1iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf1iter.next().map(val), None);

    let mut leaf2iter = t.iter_from_leaf_to_root(2).unwrap();
    assert_eq!(
        leaf2iter.next().map(val),
        t.node_value_from_bottom(0, 2).ok()
    );
    assert_eq!(
        leaf2iter.next().map(val),
        t.node_value_from_bottom(1, 1).ok()
    );
    assert_eq!(
        leaf2iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(
        leaf2iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf2iter.next().map(val), None);

    let mut leaf3iter = t.iter_from_leaf_to_root(3).unwrap();
    assert_eq!(
        leaf3iter.next().map(val),
        t.node_value_from_bottom(0, 3).ok()
    );
    assert_eq!(
        leaf3iter.next().map(val),
        t.node_value_from_bottom(1, 1).ok()
    );
    assert_eq!(
        leaf3iter.next().map(val),
        t.node_value_from_bottom(2, 0).ok()
    );
    assert_eq!(
        leaf3iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf3iter.next().map(val), None);

    let mut leaf4iter = t.iter_from_leaf_to_root(4).unwrap();
    assert_eq!(
        leaf4iter.next().map(val),
        t.node_value_from_bottom(0, 4).ok()
    );
    assert_eq!(
        leaf4iter.next().map(val),
        t.node_value_from_bottom(1, 2).ok()
    );
    assert_eq!(
        leaf4iter.next().map(val),
        t.node_value_from_bottom(2, 1).ok()
    );
    assert_eq!(
        leaf4iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf4iter.next().map(val), None);

    let mut leaf5iter = t.iter_from_leaf_to_root(5).unwrap();
    assert_eq!(
        leaf5iter.next().map(val),
        t.node_value_from_bottom(0, 5).ok()
    );
    assert_eq!(
        leaf5iter.next().map(val),
        t.node_value_from_bottom(1, 2).ok()
    );
    assert_eq!(
        leaf5iter.next().map(val),
        t.node_value_from_bottom(2, 1).ok()
    );
    assert_eq!(
        leaf5iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf5iter.next().map(val), None);

    let mut leaf6iter = t.iter_from_leaf_to_root(6).unwrap();
    assert_eq!(
        leaf6iter.next().map(val),
        t.node_value_from_bottom(0, 6).ok()
    );
    assert_eq!(
        leaf6iter.next().map(val),
        t.node_value_from_bottom(1, 3).ok()
    );
    assert_eq!(
        leaf6iter.next().map(val),
        t.node_value_from_bottom(2, 1).ok()
    );
    assert_eq!(
        leaf6iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf6iter.next().map(val), None);

    let mut leaf7iter = t.iter_from_leaf_to_root(7).unwrap();
    assert_eq!(
        leaf7iter.next().map(val),
        t.node_value_from_bottom(0, 7).ok()
    );
    assert_eq!(
        leaf7iter.next().map(val),
        t.node_value_from_bottom(1, 3).ok()
    );
    assert_eq!(
        leaf7iter.next().map(val),
        t.node_value_from_bottom(2, 1).ok()
    );
    assert_eq!(
        leaf7iter.next().map(val),
        t.node_value_from_bottom(3, 0).ok()
    );
    assert_eq!(leaf7iter.next().map(val), None);

    // Error cases: Invalid access
    for i in t.leaves_count().get()..100 {
        assert_eq!(
            t.iter_from_leaf_to_root(i).unwrap_err(),
            MerkleTreeAccessError::IterStartIndexOutOfRange(i, t.leaves_count().get())
        );
    }
}

#[test]
fn node_and_siblings_one_leaf() {
    let v00 = H256::zero();

    let t = MerkleTree::from_leaves(vec![v00]).unwrap();

    let node = t.node_from_bottom(0, 0).unwrap();
    assert_eq!(node.abs_index(), 0);
    assert!(node.sibling().is_none());
}

#[test]
fn node_and_siblings_two_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);

    let t = MerkleTree::from_leaves(vec![v00, v01]).unwrap();

    // To get the sibling, we use this simple function
    let flip_even_odd = |i| if i % 2 == 0 { i + 1 } else { i - 1 };

    for i in 0..2 {
        let node = t.node_from_bottom(0, i).unwrap();
        assert_eq!(node.abs_index(), i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(i));
    }

    for i in 0..1 {
        let node = t.node_from_bottom(1, i).unwrap();
        assert_eq!(node.abs_index(), 2 + i);
        assert!(node.sibling().is_none());
    }
}

#[test]
fn node_and_siblings_four_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);
    let v02 = H256::from_low_u64_be(2);
    let v03 = H256::from_low_u64_be(3);

    let t = MerkleTree::from_leaves(vec![v00, v01, v02, v03]).unwrap();

    // To get the sibling, we use this simple function
    let flip_even_odd = |i| if i % 2 == 0 { i + 1 } else { i - 1 };

    for i in 0..4 {
        let node = t.node_from_bottom(0, i).unwrap();
        assert_eq!(node.abs_index(), i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(i));
    }

    for i in 0..2 {
        let node = t.node_from_bottom(1, i).unwrap();
        assert_eq!(node.abs_index(), 4 + i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(4 + i));
    }

    for i in 0..1 {
        let node = t.node_from_bottom(2, i).unwrap();
        assert_eq!(node.abs_index(), 6 + i);
        assert!(node.sibling().is_none());
    }
}

#[test]
fn node_and_siblings_eight_leaves() {
    let v00 = H256::zero();
    let v01 = H256::from_low_u64_be(1);
    let v02 = H256::from_low_u64_be(2);
    let v03 = H256::from_low_u64_be(3);
    let v04 = H256::from_low_u64_be(4);

    let t = MerkleTree::from_leaves(vec![v00, v01, v02, v03, v04]).unwrap();

    // To get the sibling, we use this simple function
    let flip_even_odd = |i| if i % 2 == 0 { i + 1 } else { i - 1 };

    for i in 0..8 {
        let node = t.node_from_bottom(0, i).unwrap();
        assert_eq!(node.abs_index(), i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(i));
    }

    for i in 0..4 {
        let node = t.node_from_bottom(1, i).unwrap();
        assert_eq!(node.abs_index(), 8 + i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(8 + i));
    }

    for i in 0..2 {
        let node = t.node_from_bottom(2, i).unwrap();
        assert_eq!(node.abs_index(), 12 + i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(12 + i));
    }

    for i in 0..1 {
        let node = t.node_from_bottom(3, i).unwrap();
        assert_eq!(node.abs_index(), 14 + i);
        assert!(node.sibling().is_none());
    }
}

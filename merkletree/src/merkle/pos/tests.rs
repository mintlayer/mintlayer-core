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

// This helps to make tests more readable
#![allow(clippy::single_range_in_vec_init)]

use rstest::rstest;
use std::ops::Range;

use super::*;

#[test]
fn construction_from_abs_index() {
    for tree_size_in in 1..16u32 {
        let tree_size: Result<TreeSize, _> = tree_size_in.try_into();
        let tree_size = match tree_size {
            Ok(t) => {
                assert!((tree_size_in + 1).is_power_of_two());
                t
            }
            Err(_) => {
                assert!(!(tree_size_in + 1).is_power_of_two());
                continue;
            }
        };
        for abs_index in 0..tree_size.get() {
            let success = (tree_size.get() + 1).is_power_of_two() && abs_index < tree_size.get();
            let pos = NodePosition::from_abs_index(tree_size, abs_index);
            assert_eq!(
                pos.is_some(),
                success,
                "Assertion failed for tree_size = {}, index = {}",
                tree_size,
                abs_index
            );
            if !success {
                continue;
            }
            let pos = pos.unwrap();
            assert_eq!(pos.abs_index(), abs_index);
            assert_eq!(pos.tree_size(), tree_size);
        }
    }
}

const BIG_VAL: u32 = 1000;

#[rstest]
#[case(1,  0..1, &[0..1], true)]
#[case(3,  0..2, &[0..2,  0..1], true)]
#[case(7,  0..2, &[0..4,  0..2,  0..1], true)]
#[case(15, 0..2, &[0..8,  0..4,  0..2, 0..1], true)]
#[case(31, 0..2, &[0..16, 0..8,  0..4, 0..2, 0..1], true)]
#[case(63, 0..2, &[0..32, 0..16, 0..8, 0..4, 0..2, 0..1], true)]
#[case(1,  0..1, &[1..BIG_VAL], false)]
#[case(3,  0..2, &[2..BIG_VAL,  1..BIG_VAL], false)]
#[case(7,  0..2, &[4..BIG_VAL,  2..BIG_VAL,  1..BIG_VAL], false)]
#[case(15, 0..2, &[8..BIG_VAL,  4..BIG_VAL,  2..BIG_VAL, 1..BIG_VAL], false)]
#[case(31, 0..2, &[16..BIG_VAL, 8..BIG_VAL,  4..BIG_VAL, 2..BIG_VAL, 1..BIG_VAL], false)]
#[case(63, 0..2, &[32..BIG_VAL, 16..BIG_VAL, 8..BIG_VAL, 4..BIG_VAL, 2..BIG_VAL, 1..BIG_VAL], false)]
fn construction_from_position(
    #[case] tree_size: u32,
    #[case] levels: Range<u32>,
    #[case] indices_in_levels: &[Range<u32>],
    #[case] success: bool,
) {
    let tree_size: TreeSize = tree_size.try_into().unwrap();

    for level in levels {
        for index in indices_in_levels[level as usize].clone() {
            let pos = NodePosition::from_position(tree_size, level, index);
            assert_eq!(
                pos.is_some(),
                success,
                "Assertion failed for tree_size = {}, level = {}, index = {}",
                tree_size,
                level,
                index
            );
            if !success {
                continue;
            }
            let pos = pos.unwrap();
            assert_eq!(pos.position(), (level, index));
            assert_eq!(pos.tree_size(), tree_size);
        }
    }
}

#[test]
fn abs_index_to_and_from_pos() {
    // Exhaustive to a limit to avoid making the test take too long
    for tree_log_size in 1..10u32 {
        let tree_size: TreeSize = ((1 << tree_log_size) - 1u32).try_into().unwrap();
        for abs_pos in 0..tree_size.get() {
            let pos_from_abs = NodePosition::from_abs_index(tree_size, abs_pos).unwrap();
            let (level, index) = pos_from_abs.position();
            let pos_from_levels = NodePosition::from_position(tree_size, level, index).unwrap();
            assert_eq!(pos_from_abs, pos_from_levels);
        }
    }
}

#[test]
fn parent_iter_one_leaf() {
    let t_size = 1u32.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.into_iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), None);
}

#[test]
fn parent_iter_two_leaves() {
    let t_size = 3u32.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.into_iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf0iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 1).unwrap();
    let mut leaf1iter = n.into_iter_parents();
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 0, 1));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf1iter.next(), None);
}

#[test]
fn parent_iter_four_leaves() {
    let t_size = 7u32.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.into_iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf0iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 1).unwrap();
    let mut leaf1iter = n.into_iter_parents();
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 0, 1));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf1iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 2).unwrap();
    let mut leaf2iter = n.into_iter_parents();
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 0, 2));
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf2iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 3).unwrap();
    let mut leaf3iter = n.into_iter_parents();
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 0, 3));
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf3iter.next(), None);
}

#[test]
fn parent_iter_eight_leaves() {
    let t_size = 15u32.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.into_iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 1).unwrap();
    let mut leaf1iter = n.into_iter_parents();
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 0, 1));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf1iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 2).unwrap();
    let mut leaf2iter = n.into_iter_parents();
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 0, 2));
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf2iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 3).unwrap();
    let mut leaf3iter = n.into_iter_parents();
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 0, 3));
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf3iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 4).unwrap();
    let mut leaf4iter = n.into_iter_parents();
    assert_eq!(leaf4iter.next(), NodePosition::from_position(t_size, 0, 4));
    assert_eq!(leaf4iter.next(), NodePosition::from_position(t_size, 1, 2));
    assert_eq!(leaf4iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf4iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf4iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 5).unwrap();
    let mut leaf5iter = n.into_iter_parents();
    assert_eq!(leaf5iter.next(), NodePosition::from_position(t_size, 0, 5));
    assert_eq!(leaf5iter.next(), NodePosition::from_position(t_size, 1, 2));
    assert_eq!(leaf5iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf5iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf5iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 6).unwrap();
    let mut leaf6iter = n.into_iter_parents();
    assert_eq!(leaf6iter.next(), NodePosition::from_position(t_size, 0, 6));
    assert_eq!(leaf6iter.next(), NodePosition::from_position(t_size, 1, 3));
    assert_eq!(leaf6iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf6iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf6iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 7).unwrap();
    let mut leaf7iter = n.into_iter_parents();
    assert_eq!(leaf7iter.next(), NodePosition::from_position(t_size, 0, 7));
    assert_eq!(leaf7iter.next(), NodePosition::from_position(t_size, 1, 3));
    assert_eq!(leaf7iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf7iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf7iter.next(), None);
}

#[test]
fn node_and_siblings_one_leaf() {
    let t_size = 1u32.try_into().unwrap();
    let node = NodePosition::from_abs_index(t_size, 0).unwrap();

    assert_eq!(node.abs_index(), 0);
    assert!(node.sibling().is_none());
}

#[test]
fn node_and_siblings_two_leaves() {
    let t_size = 3u32.try_into().unwrap();

    // To get the sibling, we use this simple function
    let flip_even_odd = |i| if i % 2 == 0 { i + 1 } else { i - 1 };

    for i in 0..2 {
        let node = NodePosition::from_position(t_size, 0, i).unwrap();
        assert_eq!(node.abs_index(), i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(i));
    }

    for i in 0..1 {
        let node = NodePosition::from_position(t_size, 1, i).unwrap();
        assert_eq!(node.abs_index(), 2 + i);
        assert!(node.sibling().is_none());
    }
}

#[test]
fn node_and_siblings_four_leaves() {
    let t_size = 7u32.try_into().unwrap();

    // To get the sibling, we use this simple function
    let flip_even_odd = |i| if i % 2 == 0 { i + 1 } else { i - 1 };

    for i in 0..4 {
        let node = NodePosition::from_position(t_size, 0, i).unwrap();
        assert_eq!(node.abs_index(), i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(i));
    }

    for i in 0..2 {
        let node = NodePosition::from_position(t_size, 1, i).unwrap();
        assert_eq!(node.abs_index(), 4 + i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(4 + i));
    }

    for i in 0..1 {
        let node = NodePosition::from_position(t_size, 2, i).unwrap();
        assert_eq!(node.abs_index(), 6 + i);
        assert!(node.sibling().is_none());
    }
}

#[test]
fn node_and_siblings_eight_leaves() {
    let t_size = 15u32.try_into().unwrap();

    // To get the sibling, we use this simple function
    let flip_even_odd = |i| if i % 2 == 0 { i + 1 } else { i - 1 };

    for i in 0..8 {
        let node = NodePosition::from_position(t_size, 0, i).unwrap();
        assert_eq!(node.abs_index(), i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(i));
    }

    for i in 0..4 {
        let node = NodePosition::from_position(t_size, 1, i).unwrap();
        assert_eq!(node.abs_index(), 8 + i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(8 + i));
    }

    for i in 0..2 {
        let node = NodePosition::from_position(t_size, 2, i).unwrap();
        assert_eq!(node.abs_index(), 12 + i);
        assert_eq!(node.sibling().unwrap().abs_index(), flip_even_odd(12 + i));
    }

    for i in 0..1 {
        let node = NodePosition::from_position(t_size, 3, i).unwrap();
        assert_eq!(node.abs_index(), 14 + i);
        assert!(node.sibling().is_none());
    }
}

#[test]
fn from_abs_index_construction_boundaries() {
    for p in 1..10 {
        let t_size: TreeSize = ((1 << p) - 1u32).try_into().unwrap();

        for i in 0..t_size.get() {
            assert!(NodePosition::from_abs_index(t_size, i).is_some());
        }
        for i in t_size.get()..t_size.get() + 1000 {
            assert!(NodePosition::from_abs_index(t_size, i).is_none());
        }
    }
}

#[test]
fn absolute_index_from_bottom() {
    // Tree size: 1
    let s: TreeSize = 1u32.try_into().expect("is not zero");
    assert_eq!(NodePosition::from_position(s, 0, 0).unwrap().abs_index(), 0);

    // Tree size: 3
    let s: TreeSize = 3u32.try_into().expect("is not zero");
    assert_eq!(NodePosition::from_position(s, 0, 0).unwrap().abs_index(), 0);
    assert_eq!(NodePosition::from_position(s, 0, 1).unwrap().abs_index(), 1);

    assert_eq!(NodePosition::from_position(s, 1, 0).unwrap().abs_index(), 2);

    // Tree size: 7
    let s: TreeSize = 7u32.try_into().expect("is not zero");
    assert_eq!(NodePosition::from_position(s, 0, 0).unwrap().abs_index(), 0);
    assert_eq!(NodePosition::from_position(s, 0, 1).unwrap().abs_index(), 1);
    assert_eq!(NodePosition::from_position(s, 0, 2).unwrap().abs_index(), 2);
    assert_eq!(NodePosition::from_position(s, 0, 3).unwrap().abs_index(), 3);

    assert_eq!(NodePosition::from_position(s, 1, 0).unwrap().abs_index(), 4);
    assert_eq!(NodePosition::from_position(s, 1, 1).unwrap().abs_index(), 5);

    assert_eq!(NodePosition::from_position(s, 2, 0).unwrap().abs_index(), 6);

    // Tree size: 15
    let s: TreeSize = 15u32.try_into().expect("is not zero");
    assert_eq!(NodePosition::from_position(s, 0, 0).unwrap().abs_index(), 0);
    assert_eq!(NodePosition::from_position(s, 0, 1).unwrap().abs_index(), 1);
    assert_eq!(NodePosition::from_position(s, 0, 2).unwrap().abs_index(), 2);
    assert_eq!(NodePosition::from_position(s, 0, 3).unwrap().abs_index(), 3);
    assert_eq!(NodePosition::from_position(s, 0, 4).unwrap().abs_index(), 4);
    assert_eq!(NodePosition::from_position(s, 0, 5).unwrap().abs_index(), 5);
    assert_eq!(NodePosition::from_position(s, 0, 6).unwrap().abs_index(), 6);
    assert_eq!(NodePosition::from_position(s, 0, 7).unwrap().abs_index(), 7);

    assert_eq!(NodePosition::from_position(s, 1, 0).unwrap().abs_index(), 8);
    assert_eq!(NodePosition::from_position(s, 1, 1).unwrap().abs_index(), 9);
    assert_eq!(
        NodePosition::from_position(s, 1, 2).unwrap().abs_index(),
        10
    );
    assert_eq!(
        NodePosition::from_position(s, 1, 3).unwrap().abs_index(),
        11
    );

    assert_eq!(
        NodePosition::from_position(s, 2, 0).unwrap().abs_index(),
        12
    );
    assert_eq!(
        NodePosition::from_position(s, 2, 1).unwrap().abs_index(),
        13
    );

    assert_eq!(
        NodePosition::from_position(s, 3, 0).unwrap().abs_index(),
        14
    );
}

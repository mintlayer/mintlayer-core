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

#[test]
fn parent_iter_one_leaf() {
    let t_size = 1.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), None);
}

#[test]
fn parent_iter_two_leaves() {
    let t_size = 3.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf0iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 1).unwrap();
    let mut leaf1iter = n.iter_parents();
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 0, 1));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf1iter.next(), None);
}

#[test]
fn parent_iter_four_leaves() {
    let t_size = 7.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf0iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 1).unwrap();
    let mut leaf1iter = n.iter_parents();
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 0, 1));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf1iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf1iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 2).unwrap();
    let mut leaf2iter = n.iter_parents();
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 0, 2));
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf2iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf2iter.next(), None);

    let n = NodePosition::from_abs_index(t_size, 3).unwrap();
    let mut leaf3iter = n.iter_parents();
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 0, 3));
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf3iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf3iter.next(), None);
}

#[test]
fn parent_iter_eight_leaves() {
    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 0).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 1).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 1));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 2).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 2));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 3).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 3));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 1));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 0));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 4).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 4));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 2));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 5).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 5));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 2));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 6).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 6));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 3));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);

    let t_size = 15.try_into().unwrap();

    let n = NodePosition::from_abs_index(t_size, 7).unwrap();
    let mut leaf0iter = n.iter_parents();
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 0, 7));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 1, 3));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 2, 1));
    assert_eq!(leaf0iter.next(), NodePosition::from_position(t_size, 3, 0));
    assert_eq!(leaf0iter.next(), None);
}

#[test]
fn node_and_siblings_one_leaf() {
    let t_size = 1.try_into().unwrap();
    let node = NodePosition::from_abs_index(t_size, 0).unwrap();

    assert_eq!(node.abs_index(), 0);
    assert!(node.sibling().is_none());
}

#[test]
fn node_and_siblings_two_leaves() {
    let t_size = 3.try_into().unwrap();

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
    let t_size = 7.try_into().unwrap();

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
    let t_size = 15.try_into().unwrap();

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

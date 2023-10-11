// Copyright (c) 2023 RBB S.r.l
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

use std::collections::BTreeSet;

/// Generic depth-first traversal over a DAG in post order.
///
/// This function produces an iterator which yields elements of a post-order traversal of given
/// directed acyclic graph starting at given root. Graph edges are characterized by the `children`
/// parameter which is a function that, given an element (node), produces an iterator over elements
/// that are pointed to by it.
///
/// Note the input has to be a DAG. The algorithm does not check for cycles.
pub fn dag_depth_postorder_multiroot<'a, T, RI, I, F>(
    roots: RI,
    children: F,
) -> impl Iterator<Item = T> + 'a
where
    T: Clone + Ord + 'a,
    RI::IntoIter: DoubleEndedIterator,
    RI: IntoIterator<Item = T> + 'a,
    I: IntoIterator<Item = T> + 'a,
    F: Fn(&T) -> I + 'a,
{
    // Stack of items paired with iterator over the item's children that have to be visited before
    // the item itself is emitted.
    let mut stack: Vec<_> =
        roots.into_iter().rev().map(|x| (children(&x).into_iter(), x)).collect();

    // Keep track of already visited items
    let mut visited: BTreeSet<T> = stack.iter().map(|x| x.1.clone()).collect();

    let iter_fn = move || {
        stack.pop().map(|(mut top_children, mut top_item)| {
            // Keep pushing items onto the stack until we find one with no further children.
            while let Some(next_top_item) = top_children.next() {
                if visited.contains(&next_top_item) {
                    continue;
                }

                stack.push((top_children, top_item));
                visited.insert(next_top_item.clone());

                top_item = next_top_item;
                top_children = children(&top_item).into_iter();
            }

            top_item
        })
    };

    std::iter::from_fn(iter_fn)
}

pub fn dag_depth_postorder<'a, T, I, F>(root: T, children: F) -> impl Iterator<Item = T> + 'a
where
    T: Clone + Ord + 'a,
    I: IntoIterator<Item = T> + 'a,
    F: Fn(&T) -> I + 'a,
{
    dag_depth_postorder_multiroot(std::iter::once(root), children)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sequence() {
        let children = |n: &i32| std::iter::once(*n + 1).filter(|n| *n < 5);
        let traversal: Vec<_> = dag_depth_postorder(0, children).collect();
        assert_eq!(traversal, vec![4, 3, 2, 1, 0]);
    }

    #[test]
    fn lattice() {
        let children = |n: &i32| {
            let children = match n {
                0 => &[1, 2, 3][..],
                1..=3 => &[4][..],
                4 => &[][..],
                _ => panic!("unreachable graph node"),
            };
            children.iter().copied()
        };
        let traversal: Vec<_> = dag_depth_postorder(0, children).collect();
        assert_eq!(traversal, vec![4, 1, 2, 3, 0]);
    }

    #[test]
    fn diamond_refs() {
        let children = |n: &&i32| {
            let children = match n {
                0 => &[1, 2][..],
                1 | 2 => &[3][..],
                3 => &[][..],
                _ => panic!("unreachable graph node"),
            };
            children.iter()
        };
        let traversal: Vec<_> = dag_depth_postorder(&0, children).collect();
        assert_eq!(traversal, vec![&3, &1, &2, &0]);
    }

    #[test]
    fn multiroot() {
        let children = |n: &i32| {
            let children = match n {
                0 => &[1, 2, 3][..],
                1..=3 => &[4][..],
                4 => &[][..],
                5 => &[3][..],
                6 => &[5][..],
                7 => &[][..],
                8 => &[][..],
                _ => panic!("unreachable graph node"),
            };
            children.iter().copied()
        };
        let traversal: Vec<_> = dag_depth_postorder_multiroot([0, 6, 7], children).collect();
        assert_eq!(traversal, vec![4, 1, 2, 3, 0, 5, 6, 7]);
    }
}

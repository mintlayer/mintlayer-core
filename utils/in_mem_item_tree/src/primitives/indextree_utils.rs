// Copyright (c) 2021-2024 RBB S.r.l
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

use indextree::{Arena, NodeId};

use utils::ensure;

/// Starting from the specified node, iterate over the corresponding subtree, depth first, and call
/// the provided function on each node.
/// If the function returns false, the corresponding subtree will not be descended into.
/// Note: removed nodes are never iterated over; if the passed `root_id` refers to a removed node,
/// the function won't be called even once.
pub fn for_all_nodes_depth_first<T, E>(
    arena: &Arena<T>,
    root_id: NodeId,
    mut handler: impl FnMut(NodeId) -> Result<bool, E>,
) -> Result<(), E>
where
    E: std::error::Error + From<Error>,
{
    ensure!(!root_id.is_removed(arena), Error::NodeIsRemoved(root_id));

    if !handler(root_id)? {
        return Ok(());
    }

    let mut stack = Vec::new();
    stack.push(root_id.children(arena));

    while !stack.is_empty() {
        let cur_node_id = stack.last_mut().expect("The stack is known to be non-empty").next();

        if let Some(cur_node_id) = cur_node_id {
            if handler(cur_node_id)? {
                stack.push(cur_node_id.children(arena));
            }
        } else {
            stack.pop();
        }
    }

    Ok(())
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("Node id {0} is removed")]
    NodeIsRemoved(NodeId),
}

#[cfg(test)]
mod tests {
    use ::test_utils::assert_matches;

    use super::*;

    #[test]
    fn test_for_all_depth_first() {
        // a1---a2---a3---a4---a5
        //  \---c1---c2    \---b1
        //       \---d1---d2

        let mut arena = Arena::new();

        let a1 = arena.new_node(1);
        let a2 = arena.new_node(2);
        let a3 = arena.new_node(3);
        let a4 = arena.new_node(4);
        let a5 = arena.new_node(5);
        let b1 = arena.new_node(11);
        let c1 = arena.new_node(111);
        let c2 = arena.new_node(222);
        let d1 = arena.new_node(1111);
        let d2 = arena.new_node(2222);

        a1.checked_append(a2, &mut arena).unwrap();
        a1.checked_append(c1, &mut arena).unwrap();
        a2.checked_append(a3, &mut arena).unwrap();
        a3.checked_append(a4, &mut arena).unwrap();
        a4.checked_append(a5, &mut arena).unwrap();
        a4.checked_append(b1, &mut arena).unwrap();
        c1.checked_append(c2, &mut arena).unwrap();
        c1.checked_append(d1, &mut arena).unwrap();
        d1.checked_append(d2, &mut arena).unwrap();

        let result = for_all_nodes_depth_first_collect(&arena, a1, |_| true).unwrap();
        let expected = [1, 2, 3, 4, 5, 11, 111, 222, 1111, 2222];
        assert_eq!(result, expected);

        // Don't descent into a3
        let result = for_all_nodes_depth_first_collect(&arena, a1, |val| val != 3).unwrap();
        let expected = [1, 2, 3, 111, 222, 1111, 2222];
        assert_eq!(result, expected);

        // Remove a4.
        a4.remove_subtree(&mut arena);
        // a4, a5, b1 are no longer returned.
        let result = for_all_nodes_depth_first_collect(&arena, a1, |_| true).unwrap();
        let expected = [1, 2, 3, 111, 222, 1111, 2222];
        assert_eq!(result, expected);

        // Iterate starting from a4, an error should be returned.
        assert_matches!(
            for_all_nodes_depth_first_collect(&arena, a4, |_| true),
            Err(Error::NodeIsRemoved(_))
        );
    }

    fn for_all_nodes_depth_first_collect<T: Copy>(
        arena: &Arena<T>,
        root_id: NodeId,
        handler: impl Fn(T) -> bool,
    ) -> Result<Vec<T>, Error> {
        let mut vec = Vec::new();

        let result = for_all_nodes_depth_first(arena, root_id, |node_id| -> Result<_, Error> {
            let val = *arena.get(node_id).unwrap().get();
            vec.push(val);
            Ok(handler(val))
        });

        result.map(|_| vec)
    }
}

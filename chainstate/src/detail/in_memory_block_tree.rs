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

use std::collections::{BTreeMap, BTreeSet};

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{BlockIndex, InMemoryBlockTreeError};
use common::{
    chain::{block::timestamp::BlockTimestamp, Block},
    primitives::{BlockHeight, Id},
};
use indextree::{Arena, Node, NodeId};
use utils::{debug_panic_or_log, log_error};

use crate::{detail::chainstateref::block_validity_matches, TransactionVerificationStrategy};

use super::chainstateref::{BlockValidity, ChainstateRef};

/// Zero or more `BlockIndex` trees sharing the same arena.
pub struct InMemoryBlockTrees {
    arena: Arena<BlockIndex>,
    roots: BTreeMap<Id<Block>, NodeId>,
}

impl InMemoryBlockTrees {
    fn new(arena: Arena<BlockIndex>, roots: BTreeMap<Id<Block>, NodeId>) -> InMemoryBlockTrees {
        Self { arena, roots }
    }

    #[allow(unused)]
    pub fn roots(&self) -> &BTreeMap<Id<Block>, NodeId> {
        &self.roots
    }

    pub fn into_single_tree(self, root_block_id: &Id<Block>) -> Option<InMemoryBlockTree> {
        self.roots
            .get(root_block_id)
            .map(|root_node_id| InMemoryBlockTree::new(self.arena, *root_node_id))
    }

    pub fn iter_trees(&self) -> impl Iterator<Item = InMemoryBlockTreeRef<'_>> {
        self.roots
            .values()
            .map(|node_id| InMemoryBlockTreeRef::new(&self.arena, *node_id))
    }

    pub fn iter_all_block_indices(&self) -> impl Iterator<Item = &'_ BlockIndex> {
        self.iter_trees().flat_map(|tree| tree.iter_all_block_indices())
    }

    pub fn as_by_height_block_id_map(
        &self,
    ) -> Result<BTreeMap<BlockHeight, BTreeSet<Id<Block>>>, InMemoryBlockTreeError> {
        let mut result = BTreeMap::<BlockHeight, BTreeSet<Id<Block>>>::new();

        for block_index in self.iter_all_block_indices() {
            result
                .entry(block_index.block_height())
                .or_default()
                .insert(*block_index.block_id());
        }

        Ok(result)
    }

    pub fn as_by_timestamp_block_id_map(
        &self,
    ) -> Result<BTreeMap<BlockTimestamp, BTreeSet<Id<Block>>>, InMemoryBlockTreeError> {
        let mut result = BTreeMap::<BlockTimestamp, BTreeSet<Id<Block>>>::new();

        for block_index in self.iter_all_block_indices() {
            result
                .entry(block_index.block_timestamp())
                .or_default()
                .insert(*block_index.block_id());
        }

        Ok(result)
    }

    pub fn assert_all_blocks_match_validity(&self, block_validity: BlockValidity) {
        if block_validity != BlockValidity::Any {
            for block_index in self.iter_all_block_indices() {
                assert!(
                    block_validity_matches(block_index, block_validity),
                    "Block {id} validity doesn't match {block_validity:?}",
                    id = block_index.block_id(),
                );
            }
        }
    }
}

/// A "reference" to a single `BlockIndex` tree.
pub struct InMemoryBlockTreeRef<'a> {
    arena: &'a Arena<BlockIndex>,
    root_id: NodeId,
}

impl<'a> InMemoryBlockTreeRef<'a> {
    fn new(arena: &'a Arena<BlockIndex>, root_id: NodeId) -> Self {
        Self { arena, root_id }
    }

    #[allow(unused)]
    pub fn root_id(&self) -> NodeId {
        self.root_id
    }

    pub fn node(&self, id: NodeId) -> Option<&'a Node<BlockIndex>> {
        self.arena.get(id)
    }

    /// Return an iterator over the entire tree, for depth-first traversal.
    /// A parent will always be visited before its children.
    /// The first visited block will always be the root block.
    pub fn iter_all_ids(&self) -> impl Iterator<Item = NodeId> + 'a {
        self.root_id.descendants(self.arena)
    }

    /// Same as iter_all_ids, but the root is excluded.
    pub fn iter_child_ids(&self) -> impl Iterator<Item = NodeId> + 'a {
        self.iter_all_ids().skip(1)
    }

    pub fn iter_all_block_indices(&self) -> impl Iterator<Item = &'a BlockIndex> {
        self.iter_all_ids().map(|node_id| {
            self.arena
                .get(node_id)
                .expect("Node being iterated over must be present in the arena")
                .get()
        })
    }

    pub fn iter_child_block_indices(&self) -> impl Iterator<Item = &'a BlockIndex> {
        self.iter_child_ids().map(|node_id| {
            self.arena
                .get(node_id)
                .expect("Node being iterated over must be present in the arena")
                .get()
        })
    }

    pub fn root_block_index(&self) -> &'a BlockIndex {
        self.arena
            .get(self.root_id)
            .expect("Inconsistent InMemoryBlockTree - root node is not in the arena")
            .get()
    }

    /// Iterate over all nodes, depth first, and call the provided function on each node.
    /// If the function returns false, the corresponding subtree will not be descended into.
    pub fn for_all<E: std::error::Error>(
        &self,
        mut handler: impl FnMut(InMemoryBlockTreeRef<'a>) -> Result<bool, E>,
    ) -> Result<(), E> {
        indextree_utils::for_all_depth_first(self.arena, self.root_id, |node_id| {
            handler(InMemoryBlockTreeRef::new(self.arena, node_id))
        })
    }
}

/// A single `BlockIndex` tree.
pub struct InMemoryBlockTree {
    arena: Arena<BlockIndex>,
    root_id: NodeId,
}

impl InMemoryBlockTree {
    fn new(arena: Arena<BlockIndex>, root_id: NodeId) -> InMemoryBlockTree {
        Self { arena, root_id }
    }

    #[allow(unused)]
    pub fn root_id(&self) -> NodeId {
        self.root_id
    }

    pub fn as_ref(&self) -> InMemoryBlockTreeRef<'_> {
        InMemoryBlockTreeRef::new(&self.arena, self.root_id)
    }

    pub fn node(&self, id: NodeId) -> Option<&Node<BlockIndex>> {
        self.as_ref().node(id)
    }

    pub fn iter_all_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.as_ref().iter_all_ids()
    }

    pub fn iter_child_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.as_ref().iter_child_ids()
    }

    pub fn iter_all_block_indices(&self) -> impl Iterator<Item = &BlockIndex> {
        self.as_ref().iter_all_block_indices()
    }

    pub fn iter_child_block_indices(&self) -> impl Iterator<Item = &BlockIndex> {
        self.as_ref().iter_child_block_indices()
    }

    pub fn root_block_index(&self) -> &BlockIndex {
        self.as_ref().root_block_index()
    }

    pub fn for_all<E: std::error::Error>(
        &self,
        handler: impl FnMut(InMemoryBlockTreeRef<'_>) -> Result<bool, E>,
    ) -> Result<(), E> {
        self.as_ref().for_all(handler)
    }
}

fn append_child<T>(
    parent: NodeId,
    child: NodeId,
    arena: &mut Arena<T>,
) -> Result<(), InMemoryBlockTreeError> {
    parent
        .checked_append(child, arena)
        .map_err(|err| InMemoryBlockTreeError::IndexTreeNodeError(err.to_string()))
}

/// Iterate starting from each leaf block downwards and collect the corresponding block indices.
/// The `is_depth_ok` function is called for each traversed BlockIndex; it's supposed to
/// check the "depth" of the given block (i.e. some property that changes strictly monotonically
/// when going from child to parent, such as the height or the timestamp) and return true if
/// the caller is still interested in blocks at this "depth" or false if it is not.
#[log_error]
pub fn get_block_tree_top<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    is_depth_ok: impl Fn(&BlockIndex) -> bool,
    block_validity: BlockValidity,
) -> Result<InMemoryBlockTrees, InMemoryBlockTreeError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    let mut arena = Arena::new();
    let mut roots = BTreeMap::new();

    let mut seen_blocks = BTreeMap::<Id<Block>, NodeId>::new();

    let leaf_block_ids = chainstate_ref.get_leaf_block_ids()?;

    for leaf_block_id in leaf_block_ids {
        let leaf_block_index = chainstate_ref.get_existing_block_index(&leaf_block_id)?;

        let effective_leaf_block_index = if let Some(block_index) = chainstate_ref
            .find_first_parent_with_validity(leaf_block_index, block_validity, &is_depth_ok)?
        {
            block_index
        } else {
            continue;
        };

        if !is_depth_ok(&effective_leaf_block_index) {
            continue;
        }

        let effective_leaf_block_id = effective_leaf_block_index.block_id();

        if seen_blocks.contains_key(effective_leaf_block_id) {
            continue;
        }

        let mut prev_block_id = *effective_leaf_block_index.prev_block_id();
        let mut branch_root_block_id = *effective_leaf_block_id;
        let mut branch_root_node_id = arena.new_node(effective_leaf_block_index);

        let is_standalone_branch = loop {
            let cur_block_id = if let Some(non_genesis_parent_id) =
                prev_block_id.classify(chainstate_ref.chain_config()).chain_block_id()
            {
                non_genesis_parent_id
            } else {
                break true;
            };

            let cur_block_index = chainstate_ref.get_existing_block_index(&cur_block_id)?;
            prev_block_id = *cur_block_index.prev_block_id();

            if !is_depth_ok(&cur_block_index) {
                break true;
            }

            if let Some(existing_node_id) = seen_blocks.get(&cur_block_id) {
                append_child(*existing_node_id, branch_root_node_id, &mut arena)?;
                break false;
            }

            let cur_node_id = arena.new_node(cur_block_index);
            append_child(cur_node_id, branch_root_node_id, &mut arena)?;
            branch_root_block_id = cur_block_id;
            branch_root_node_id = cur_node_id;

            seen_blocks.insert(cur_block_id, cur_node_id);
        };

        if is_standalone_branch {
            roots.insert(branch_root_block_id, branch_root_node_id);
        }
    }

    Ok(InMemoryBlockTrees::new(arena, roots))
}

/// Collect a single branch of the block index tree.
#[log_error]
pub fn get_block_tree_branch<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    root_block_id: &Id<Block>,
    block_validity: BlockValidity,
) -> Result<InMemoryBlockTree, InMemoryBlockTreeError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    let root_block_index = chainstate_ref.get_existing_block_index(root_block_id)?;
    let root_block_height = root_block_index.block_height();

    let trees = get_block_tree_top(
        chainstate_ref,
        |block_index| block_index.block_height() >= root_block_height,
        block_validity,
    )?;
    let tree = trees.into_single_tree(root_block_id);

    if let Some(tree) = tree {
        Ok(tree)
    } else {
        debug_panic_or_log!("Expecting {root_block_id} to be among found subtrees but it's not");

        Err(InMemoryBlockTreeError::InvariantError(format!(
            "subtree missing for block {}",
            *root_block_id
        )))
    }
}

mod indextree_utils {
    use indextree::{Arena, NodeId};

    pub fn for_all_depth_first<T, E: std::error::Error>(
        arena: &Arena<T>,
        root_id: NodeId,
        mut handler: impl FnMut(NodeId) -> Result<bool, E>,
    ) -> Result<(), E> {
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

    #[cfg(test)]
    mod tests {
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

            let result = for_all_depth_first_collect(&arena, a1, |_| true);
            let expected = [1, 2, 3, 4, 5, 11, 111, 222, 1111, 2222];
            assert_eq!(result, expected);

            // Don't descent into a3
            let result = for_all_depth_first_collect(&arena, a1, |val| val != 3);
            let expected = [1, 2, 3, 111, 222, 1111, 2222];
            assert_eq!(result, expected);
        }

        fn for_all_depth_first_collect<T: Copy>(
            arena: &Arena<T>,
            root_id: NodeId,
            handler: impl Fn(T) -> bool,
        ) -> Vec<T> {
            let mut result = Vec::new();

            for_all_depth_first(arena, root_id, |node_id| {
                let val = *arena.get(node_id).unwrap().get();
                result.push(val);
                std::io::Result::Ok(handler(val))
            })
            .unwrap();

            result
        }
    }
}

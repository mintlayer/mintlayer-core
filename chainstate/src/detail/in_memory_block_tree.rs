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

//! Here we have a number of types that represent a block tree in memory; the main purpose of this
//! is to be able to iterate over descendants of a particular block.
//!
//! The types use the `indextree` crate under the hood. In `indextree` the actual nodes are
//! stored inside an arena and can be referenced via a `NodeId`. The nodes in our tree hold
//! `BlockIndex`es, not the whole blocks.
//!
//! We have the following types:
//! * `InMemoryBlockTrees` - this represents one or more unrelated trees that share the same arena.
//! This type is needed when collecting the "top" of an actual block tree starting from a particular
//! height (which may produce multiple branches without a common root).
//! * `InMemoryBlockTree` - this represents a single tree and can be produced from `InMemoryBlockTrees`
//! by choosing one of its roots.
//! * `InMemoryBlockTreeRef` - this represents a reference to a particular branch of a tree.

// Note: `InMemoryBlockTreeRef` can represent a branch of a bigger tree; this means that the
// `indextree::NodeId` and `indextree::Node` that correspond to the root of the branch may actually
// have a parent. So, if those `indextree` primitives are used directly, it's possible to accidentally
// step out of the corresponding "logical" branch. This is why we wrap `NodeId` in a custom struct,
// which also holds additional information about the root of the logical branch, and don't expose
// `Node` at all.

use std::collections::{BTreeMap, BTreeSet};

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{BlockIndex, InMemoryBlockTreeError};
use common::{
    chain::{block::timestamp::BlockTimestamp, Block},
    primitives::{BlockHeight, Id},
};
use indextree::NodeId;
use utils::log_error;

use crate::{detail::chainstateref::block_validity_matches, TransactionVerificationStrategy};

use super::chainstateref::{BlockValidity, ChainstateRef};

type Arena = indextree::Arena<BlockIndex>;
type Node = indextree::Node<BlockIndex>;

/// The wrapped `NodeId`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InMemoryBlockTreeNodeId {
    node_id: indextree::NodeId,
    branch_root_node_id: indextree::NodeId,
}

impl InMemoryBlockTreeNodeId {
    fn new_root(node_id: indextree::NodeId) -> Self {
        Self {
            node_id,
            branch_root_node_id: node_id,
        }
    }
}

/// Zero or more trees sharing the same arena.
pub struct InMemoryBlockTrees {
    arena: Arena,
    roots: BTreeMap<Id<Block>, NodeId>,
}

impl InMemoryBlockTrees {
    fn new(arena: Arena, roots: BTreeMap<Id<Block>, NodeId>) -> InMemoryBlockTrees {
        #[cfg(debug_assertions)]
        {
            // Ensure that all roots are present in the arena and are actual roots, i.e. nodes
            // without parents.
            for node_id in roots.values() {
                assert!(arena.get(*node_id).expect("node must be in the arena").parent().is_none());
            }
        }

        Self { arena, roots }
    }

    #[allow(unused)]
    pub fn roots(&self) -> impl Iterator<Item = (&Id<Block>, InMemoryBlockTreeNodeId)> {
        self.roots
            .iter()
            .map(|(block_id, node_id)| (block_id, InMemoryBlockTreeNodeId::new_root(*node_id)))
    }

    /// Turn itself into a single tree corresponding to the specified block id.
    /// Note that the other trees will still occupy space in the arena.
    pub fn into_single_tree(
        self,
        root_block_id: &Id<Block>,
    ) -> Result<InMemoryBlockTree, InMemoryBlockTreeError> {
        let root_node_id = *self.roots.get(root_block_id).ok_or(
            InMemoryBlockTreeError::BlockIdDoesntCorrespondToRoot(*root_block_id),
        )?;

        Ok(InMemoryBlockTree::new(self.arena, root_node_id))
    }

    /// Return a single tree as a reference.
    pub fn single_tree(
        &self,
        root_block_id: &Id<Block>,
    ) -> Result<InMemoryBlockTreeRef<'_>, InMemoryBlockTreeError> {
        let root_node_id = *self.roots.get(root_block_id).ok_or(
            InMemoryBlockTreeError::BlockIdDoesntCorrespondToRoot(*root_block_id),
        )?;

        Ok(InMemoryBlockTreeRef::new(&self.arena, root_node_id))
    }

    pub fn trees_iter(&self) -> impl Iterator<Item = InMemoryBlockTreeRef<'_>> {
        self.roots
            .values()
            .map(|node_id| InMemoryBlockTreeRef::new(&self.arena, *node_id))
    }

    pub fn all_block_indices_iter(&self) -> impl Iterator<Item = &'_ BlockIndex> {
        self.trees_iter().flat_map(|tree| tree.all_block_indices_iter())
    }

    pub fn as_by_height_block_id_map(
        &self,
    ) -> Result<BTreeMap<BlockHeight, BTreeSet<Id<Block>>>, InMemoryBlockTreeError> {
        let mut result = BTreeMap::<BlockHeight, BTreeSet<Id<Block>>>::new();

        for block_index in self.all_block_indices_iter() {
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

        for block_index in self.all_block_indices_iter() {
            result
                .entry(block_index.block_timestamp())
                .or_default()
                .insert(*block_index.block_id());
        }

        Ok(result)
    }

    pub fn assert_all_blocks_match_validity(&self, block_validity: BlockValidity) {
        if block_validity != BlockValidity::Any {
            for block_index in self.all_block_indices_iter() {
                assert!(
                    block_validity_matches(block_index, block_validity),
                    "Block {id} validity doesn't match {block_validity:?}",
                    id = block_index.block_id(),
                );
            }
        }
    }

    pub fn find_node_id(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<(InMemoryBlockTreeRef<'_>, InMemoryBlockTreeNodeId)>, InMemoryBlockTreeError>
    {
        for tree in self.trees_iter() {
            if let Some(node_id) = tree.find_node_id(block_id)? {
                return Ok(Some((tree, node_id)));
            }
        }

        Ok(None)
    }
}

/// A single tree.
pub struct InMemoryBlockTree {
    arena: Arena,
    root_id: NodeId,
}

impl InMemoryBlockTree {
    fn new(arena: Arena, root_id: NodeId) -> InMemoryBlockTree {
        #[cfg(debug_assertions)]
        {
            // Ensure that the root is present in the arena and is actually a root, i.e. a node
            // without a parent.
            assert!(arena.get(root_id).expect("node must be in the arena").parent().is_none());
        }

        Self { arena, root_id }
    }

    pub fn as_ref(&self) -> InMemoryBlockTreeRef<'_> {
        InMemoryBlockTreeRef::new(&self.arena, self.root_id)
    }

    pub fn get_parent(
        &self,
        node_id: InMemoryBlockTreeNodeId,
    ) -> Result<Option<InMemoryBlockTreeNodeId>, InMemoryBlockTreeError> {
        self.as_ref().get_parent(node_id)
    }

    pub fn subtree(
        &self,
        id: InMemoryBlockTreeNodeId,
    ) -> Result<InMemoryBlockTreeRef<'_>, InMemoryBlockTreeError> {
        self.as_ref().subtree(id)
    }

    pub fn all_node_ids_iter(&self) -> impl Iterator<Item = InMemoryBlockTreeNodeId> + '_ {
        self.as_ref().all_node_ids_iter()
    }

    pub fn all_child_node_ids_iter(&self) -> impl Iterator<Item = InMemoryBlockTreeNodeId> + '_ {
        self.as_ref().all_child_node_ids_iter()
    }

    pub fn all_block_indices_iter(&self) -> impl Iterator<Item = &BlockIndex> {
        self.as_ref().all_block_indices_iter()
    }

    pub fn all_child_block_indices_iter(&self) -> impl Iterator<Item = &BlockIndex> {
        self.as_ref().all_child_block_indices_iter()
    }

    pub fn root_block_index(&self) -> Result<&BlockIndex, InMemoryBlockTreeError> {
        self.as_ref().root_block_index()
    }

    pub fn for_all<E: std::error::Error>(
        &self,
        handler: impl FnMut(InMemoryBlockTreeNodeId) -> Result<bool, E>,
    ) -> Result<(), E> {
        self.as_ref().for_all(handler)
    }

    pub fn find_node_id(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<InMemoryBlockTreeNodeId>, InMemoryBlockTreeError> {
        self.as_ref().find_node_id(block_id)
    }
}

/// A "reference" to a single tree.
#[derive(Clone, Copy)]
pub struct InMemoryBlockTreeRef<'a> {
    arena: &'a Arena,
    root_id: NodeId,
}

impl<'a> InMemoryBlockTreeRef<'a> {
    fn new(arena: &'a Arena, root_id: NodeId) -> Self {
        // Check that the arena has a node with this id.
        // Note that unlike `InMemoryBlockTree`, here root_id may not be an actual root node
        // (i.e. it may have a parent).
        debug_assert!(arena.get(root_id).is_some());

        Self { arena, root_id }
    }

    #[allow(unused)]
    pub fn root_node_id(&self) -> InMemoryBlockTreeNodeId {
        InMemoryBlockTreeNodeId::new_root(self.root_id)
    }

    pub fn get_parent(
        &self,
        node_id: InMemoryBlockTreeNodeId,
    ) -> Result<Option<InMemoryBlockTreeNodeId>, InMemoryBlockTreeError> {
        let result = if node_id.node_id == self.root_id {
            None
        } else {
            let node = get_node_from_arena(self.arena, node_id.node_id)?;
            let parent_id = node.parent().ok_or(InMemoryBlockTreeError::NonRootWithoutParent(
                node_id.node_id,
            ))?;
            Some(InMemoryBlockTreeNodeId {
                node_id: parent_id,
                branch_root_node_id: self.root_id,
            })
        };

        Ok(result)
    }

    pub fn get_block_index(
        &self,
        node_id: InMemoryBlockTreeNodeId,
    ) -> Result<&'a BlockIndex, InMemoryBlockTreeError> {
        let node = get_node_from_arena(self.arena, node_id.node_id)?;
        Ok(node.get())
    }

    pub fn subtree(
        &self,
        id: InMemoryBlockTreeNodeId,
    ) -> Result<InMemoryBlockTreeRef<'a>, InMemoryBlockTreeError> {
        self.ensure_node_in_subtree(id)?;
        Ok(Self::new(self.arena, id.node_id))
    }

    /// Return an iterator over node ids of direct children of the given node.
    pub fn child_node_ids_iter_for(
        &self,
        id: InMemoryBlockTreeNodeId,
    ) -> Result<impl Iterator<Item = InMemoryBlockTreeNodeId> + 'a, InMemoryBlockTreeError> {
        self.ensure_node_in_subtree(id)?;

        let branch_root_node_id = self.root_id;
        Ok(
            id.node_id.children(self.arena).map(move |child_id| InMemoryBlockTreeNodeId {
                node_id: child_id,
                branch_root_node_id,
            }),
        )
    }

    /// Return an iterator over the entire tree, for depth-first traversal.
    /// A parent will always be visited before its children.
    /// The first visited block will always be the root block.
    pub fn all_node_ids_iter(&self) -> impl Iterator<Item = InMemoryBlockTreeNodeId> + 'a {
        let branch_root_node_id = self.root_id;
        self.root_id
            .descendants(self.arena)
            .map(move |child_id| InMemoryBlockTreeNodeId {
                node_id: child_id,
                branch_root_node_id,
            })
    }

    /// Same as all_ids_iter, but the root is excluded.
    pub fn all_child_node_ids_iter(&self) -> impl Iterator<Item = InMemoryBlockTreeNodeId> + 'a {
        self.all_node_ids_iter().skip(1)
    }

    pub fn all_block_indices_iter(&self) -> impl Iterator<Item = &'a BlockIndex> {
        self.all_node_ids_iter().map(|node_id| {
            self.arena
                .get(node_id.node_id)
                .expect("Node being iterated over must be present in the arena")
                .get()
        })
    }

    pub fn all_child_block_indices_iter(&self) -> impl Iterator<Item = &'a BlockIndex> {
        self.all_child_node_ids_iter().map(|node_id| {
            self.arena
                .get(node_id.node_id)
                .expect("Node being iterated over must be present in the arena")
                .get()
        })
    }

    pub fn root_block_index(&self) -> Result<&'a BlockIndex, InMemoryBlockTreeError> {
        Ok(get_node_from_arena(self.arena, self.root_id)?.get())
    }

    /// Iterate over all nodes, depth first, and call the provided function on each node.
    /// If the function returns false, the corresponding subtree will not be descended into.
    pub fn for_all<E: std::error::Error>(
        &self,
        mut handler: impl FnMut(InMemoryBlockTreeNodeId) -> Result<bool, E>,
    ) -> Result<(), E> {
        indextree_utils::for_all_depth_first(self.arena, self.root_id, |node_id| {
            handler(InMemoryBlockTreeNodeId {
                node_id,
                branch_root_node_id: self.root_id,
            })
        })
    }

    pub fn find_node_id(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<InMemoryBlockTreeNodeId>, InMemoryBlockTreeError> {
        for node_id in self.all_node_ids_iter() {
            let node = get_node_from_arena(self.arena, node_id.node_id)?;
            let block_index = node.get();

            if block_index.block_id() == block_id {
                return Ok(Some(node_id));
            }
        }

        Ok(None)
    }

    fn ensure_node_in_subtree(
        &self,
        node_id: InMemoryBlockTreeNodeId,
    ) -> Result<(), InMemoryBlockTreeError> {
        if node_id.branch_root_node_id == self.root_id {
            Ok(())
        } else {
            Err(InMemoryBlockTreeError::NodeNotInBranch {
                node_id: node_id.node_id,
                nodes_branch_root: node_id.branch_root_node_id,
                actual_branch_root: self.root_id,
            })
        }
    }
}

fn get_node_from_arena(arena: &Arena, node_id: NodeId) -> Result<&Node, InMemoryBlockTreeError> {
    arena.get(node_id).ok_or(InMemoryBlockTreeError::NodeNotInArena(node_id))
}

fn append_child<T>(
    parent: NodeId,
    child: NodeId,
    arena: &mut indextree::Arena<T>,
) -> Result<(), InMemoryBlockTreeError> {
    parent
        .checked_append(child, arena)
        .map_err(|err| InMemoryBlockTreeError::IndexTreeNodeError(err.to_string()))
}

/// Iterate starting from each specified leaf block downwards and collect the corresponding block indices.
/// The `is_depth_ok` function is called for each traversed BlockIndex; it's supposed to
/// check the "depth" of the given block (i.e. some property that changes strictly monotonically
/// when going from child to parent, such as the height or the timestamp) and return true if
/// the caller is still interested in blocks at this "depth" or false if it is not.
#[log_error]
pub fn get_block_tree_top<'a, S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    leaf_block_ids: impl Iterator<Item = &'a Id<Block>>,
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

    for leaf_block_id in leaf_block_ids {
        let leaf_block_index = chainstate_ref.get_existing_block_index(leaf_block_id)?;

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

    let leaf_block_ids = chainstate_ref.get_leaf_block_ids(root_block_height)?;

    let trees = get_block_tree_top(
        chainstate_ref,
        leaf_block_ids.iter(),
        |block_index| block_index.block_height() >= root_block_height,
        block_validity,
    )?;
    trees.into_single_tree(root_block_id)
}

mod indextree_utils {
    use indextree::Arena;

    use super::*;

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

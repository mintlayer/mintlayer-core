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

//! Here we have several wrapper types that hold the arena, as well as one or more ids of
//! "root" nodes, and provide higher-level read-only access to the contained tree.
//! The intent is to be able to represent the result of some calculation that can no longer
//! be modified, while still being able to "narrow" it down by referencing only a portion
//! of the tree. To make the latter safer, we also require that node ids that are used
//! to access internals of a particular "Tree" object must be obtained from that very object
//! (and, for example, not from its subtree, or from a bigger tree that contains this particular
//! one).
//!
//! We have the following types here:
//! * `Trees` - this represents one or more unrelated trees that share the same arena.
//! This type may be needed when collecting the "top" of a block tree starting from
//! a particular height, which may produce multiple branches without a common root.
//! * `Tree` - this represents a single tree and can be produced from `Trees`
//! by choosing one of its roots.
//! * `TreeRef` - this represents a reference to a particular branch of a tree.
//! * `TreeNodeId` - this wraps `NodeId` of the corresponding node but also holds `NodeId`
//! of the root of the tree that it has been obtained from; methods of "Tree" objects that
//! accept `TreeNodeId` will fail if the root id stored inside it doesn't match "Tree"'s
//! own root.

use std::collections::BTreeMap;

use utils::ensure;

use super::primitives::{
    self, for_all_nodes_depth_first, indextree_utils, Arena, DataItem, Flavor, NodeId, TmpError,
};

/// The wrapped `NodeId`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct TreeNodeId {
    node_id: NodeId,
    branch_root_node_id: NodeId,
}

impl TreeNodeId {
    fn new_root(node_id: NodeId) -> Self {
        Self {
            node_id,
            branch_root_node_id: node_id,
        }
    }
}

/// Zero or more trees sharing the same arena.
#[derive(Clone)]
pub struct Trees<T: DataItem, F: Flavor> {
    arena: Arena<T, F>,
    roots: BTreeMap<<T as DataItem>::Id, NodeId>,
}

impl<T, F> Trees<T, F>
where
    T: DataItem,
    F: Flavor,
{
    /// Create a new `Trees` object expecting all the passed roots to be actual roots, i.e. nodes
    /// without a parent.
    pub fn with_actual_roots(
        arena: Arena<T, F>,
        roots: BTreeMap<<T as DataItem>::Id, NodeId>,
    ) -> Result<Self, Error> {
        Self::ensure_actual_roots(&arena, &roots)?;
        Ok(Self { arena, roots })
    }

    /// Same as `with_actual_roots`, but panic in debug builds instead of returning an error.
    pub fn with_actual_roots_unchecked(
        arena: Arena<T, F>,
        roots: BTreeMap<<T as DataItem>::Id, NodeId>,
    ) -> Self {
        debug_assert_eq!(Self::ensure_actual_roots(&arena, &roots), Ok(()));
        Self { arena, roots }
    }

    /// Ensure that all roots are present in the arena and are actual roots, i.e. nodes
    /// without parents.
    fn ensure_actual_roots(
        arena: &Arena<T, F>,
        roots: &BTreeMap<<T as DataItem>::Id, NodeId>,
    ) -> Result<(), Error> {
        for node_id in roots.values() {
            ensure_is_root(arena, *node_id)?;
        }

        Ok(())
    }

    /// Return an iterator over the roots.
    pub fn roots_iter(&self) -> impl Iterator<Item = (&<T as DataItem>::Id, TreeNodeId)> {
        self.roots
            .iter()
            .map(|(item_id, node_id)| (item_id, TreeNodeId::new_root(*node_id)))
    }

    /// Return the number if roots.
    pub fn roots_count(&self) -> usize {
        self.roots.len()
    }

    /// Turn itself into a single tree corresponding to the specified item id.
    /// Note that the other trees will still occupy space in the arena.
    pub fn into_single_tree(self, root_item_id: &<T as DataItem>::Id) -> Result<Tree<T, F>, Error> {
        let root_node_id =
            *self
                .roots
                .get(root_item_id)
                .ok_or_else(|| Error::ItemIdDoesntCorrespondToRoot {
                    item_id: root_item_id.to_string(),
                })?;

        Ok(Tree::with_actual_root_unchecked(self.arena, root_node_id))
    }

    /// Return a single tree as a reference.
    pub fn single_tree(
        &self,
        root_item_id: &<T as DataItem>::Id,
    ) -> Result<TreeRef<'_, T, F>, Error> {
        let root_node_id =
            *self
                .roots
                .get(root_item_id)
                .ok_or_else(|| Error::ItemIdDoesntCorrespondToRoot {
                    item_id: root_item_id.to_string(),
                })?;

        Ok(TreeRef::new_unchecked(&self.arena, root_node_id))
    }

    /// Return an iterator over trees as `TreeRef`s.
    pub fn trees_iter(&self) -> impl Iterator<Item = TreeRef<'_, T, F>> {
        self.roots.values().map(|node_id| TreeRef::new_unchecked(&self.arena, *node_id))
    }

    /// Return an iterator over all items in the tree.
    pub fn all_items_iter(&self) -> impl Iterator<Item = &'_ T> {
        self.trees_iter().flat_map(|tree| tree.all_items_iter())
    }
}

/// A single tree.
#[derive(Clone)]
pub struct Tree<T: DataItem, F: Flavor> {
    arena: Arena<T, F>,
    root_id: NodeId,
}

impl<T, F> Tree<T, F>
where
    T: DataItem,
    F: Flavor,
{
    /// Create a new `Tree` object expecting the passed root to be an actual root, i.e. a node
    /// without a parent.
    pub fn with_actual_root(arena: Arena<T, F>, root_id: NodeId) -> Result<Self, Error> {
        ensure_is_root(&arena, root_id)?;
        Ok(Self { arena, root_id })
    }

    /// Same as `with_actual_root`, but panic in debug builds instead of returning an error.
    pub fn with_actual_root_unchecked(arena: Arena<T, F>, root_id: NodeId) -> Self {
        debug_assert_eq!(ensure_is_root(&arena, root_id), Ok(()));
        Self { arena, root_id }
    }

    /// Return the id of the root node.
    pub fn root_node_id(&self) -> TreeNodeId {
        TreeNodeId::new_root(self.root_id)
    }

    /// Return the data item corresponding to the root.
    pub fn root_item(&self) -> Result<&T, Error> {
        Ok(self.arena.get_existing(self.root_id)?.get())
    }

    /// Return self as `TreeRef`.
    pub fn as_ref(&self) -> TreeRef<'_, T, F> {
        TreeRef::new_unchecked(&self.arena, self.root_id)
    }

    // The following functions just delegate to `TreeRef`, for convenience.

    pub fn get_parent(&self, node_id: TreeNodeId) -> Result<Option<TreeNodeId>, Error> {
        self.as_ref().get_parent(node_id)
    }

    pub fn get_item(&self, node_id: TreeNodeId) -> Result<&T, Error> {
        self.as_ref().get_item(node_id)
    }

    pub fn subtree(&self, node_id: TreeNodeId) -> Result<TreeRef<'_, T, F>, Error> {
        self.as_ref().subtree(node_id)
    }

    pub fn child_node_ids_iter_for(
        &self,
        node_id: TreeNodeId,
    ) -> Result<impl Iterator<Item = TreeNodeId> + '_, Error> {
        self.as_ref().child_node_ids_iter_for(node_id)
    }

    pub fn all_node_ids_iter(&self) -> impl Iterator<Item = TreeNodeId> + '_ {
        self.as_ref().all_node_ids_iter()
    }

    pub fn all_items_iter(&self) -> impl Iterator<Item = &T> {
        self.as_ref().all_items_iter()
    }

    pub fn for_all_node_ids_until<E>(
        &self,
        handler: impl FnMut(TreeNodeId) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        E: std::error::Error + From<Error>,
    {
        self.as_ref().for_all_node_ids_until(handler)
    }
}

/// A "reference" to a single tree.
#[derive(Clone, Copy)]
pub struct TreeRef<'a, T: DataItem, F: Flavor> {
    arena: &'a Arena<T, F>,
    root_id: NodeId,
}

impl<'a, T, F> TreeRef<'a, T, F>
where
    T: DataItem,
    F: Flavor,
{
    /// Create a new `TreeRef` object ensuring that the passed root is in the arena.
    pub fn new(arena: &'a Arena<T, F>, root_id: NodeId) -> Result<Self, Error> {
        ensure_node_in_arena(arena, root_id)?;
        Ok(Self { arena, root_id })
    }

    /// Same as `new`, but panic in debug builds instead of returning an error.
    pub fn new_unchecked(arena: &'a Arena<T, F>, root_id: NodeId) -> Self {
        debug_assert_eq!(ensure_node_in_arena(arena, root_id), Ok(()));

        Self { arena, root_id }
    }

    /// Return the id of the root node.
    pub fn root_node_id(&self) -> TreeNodeId {
        TreeNodeId::new_root(self.root_id)
    }

    /// Return the data item corresponding to the root.
    pub fn root_item(&self) -> Result<&'a T, Error> {
        Ok(self.arena.get_existing(self.root_id)?.get())
    }

    /// Return the id of parent of the specified node in the context of the current tree.
    /// I.e. if the passed `node_id` corresponds to the current tree's root, `None` will be
    /// returned even if it has a parent.
    pub fn get_parent(&self, node_id: TreeNodeId) -> Result<Option<TreeNodeId>, Error> {
        self.ensure_node_in_subtree(node_id)?;

        let result = if node_id.node_id == self.root_id {
            None
        } else {
            let node = self.arena.get_existing(node_id.node_id)?;
            let parent_id = node.parent().ok_or(Error::NonRootWithoutParent(node_id.node_id))?;
            Some(TreeNodeId {
                node_id: parent_id,
                branch_root_node_id: self.root_id,
            })
        };

        Ok(result)
    }

    /// Return the item corresponding to the given node id.
    pub fn get_item(&self, node_id: TreeNodeId) -> Result<&'a T, Error> {
        self.ensure_node_in_subtree(node_id)?;
        let node = self.arena.get_existing(node_id.node_id)?;
        Ok(node.get())
    }

    /// Return a subtree starting at the specified node id, as a `TreeRef`.
    pub fn subtree(&self, node_id: TreeNodeId) -> Result<TreeRef<'a, T, F>, Error> {
        self.ensure_node_in_subtree(node_id)?;
        Ok(Self::new_unchecked(self.arena, node_id.node_id))
    }

    /// Return an iterator over node ids of direct children of the given node.
    pub fn child_node_ids_iter_for(
        &self,
        node_id: TreeNodeId,
    ) -> Result<impl Iterator<Item = TreeNodeId> + 'a, Error> {
        self.ensure_node_in_subtree(node_id)?;

        let branch_root_node_id = self.root_id;
        Ok(
            node_id.node_id.children(self.arena).map(move |child_id| TreeNodeId {
                node_id: child_id,
                branch_root_node_id,
            }),
        )
    }

    /// Return an iterator over the entire tree, for depth-first traversal.
    /// A parent will always be visited before its children.
    /// The first visited item will always be the root item.
    pub fn all_node_ids_iter(&self) -> impl Iterator<Item = TreeNodeId> + 'a {
        let branch_root_node_id = self.root_id;
        self.root_id.descendants(self.arena).map(move |child_id| TreeNodeId {
            node_id: child_id,
            branch_root_node_id,
        })
    }

    /// Same as `all_node_ids_iter`, but return references to data items instead of node ids.
    pub fn all_items_iter(&self) -> impl Iterator<Item = &'a T> {
        self.all_node_ids_iter().map(|node_id| {
            self.arena
                .get(node_id.node_id)
                .expect("Node being iterated over must be present in the arena")
                .get()
        })
    }

    /// Iterate over all nodes, depth first, and call the provided function on each node.
    /// If the function returns false, the corresponding subtree will not be descended into.
    pub fn for_all_node_ids_until<E>(
        &self,
        mut handler: impl FnMut(TreeNodeId) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        E: std::error::Error + From<Error>,
    {
        for_all_nodes_depth_first(
            self.arena,
            self.root_id,
            |node_id| -> Result<_, TmpError<E, primitives::Error>> {
                handler(TreeNodeId {
                    node_id,
                    branch_root_node_id: self.root_id,
                })
                .map_err(TmpError::OuterError)
            },
        )
        .map_err(|err| err.into_outer_error_via::<Error>())
    }

    fn ensure_node_in_subtree(&self, node_id: TreeNodeId) -> Result<(), Error> {
        if node_id.branch_root_node_id == self.root_id {
            Ok(())
        } else {
            Err(Error::NodeNotInBranch {
                node_id: node_id.node_id,
                nodes_branch_root: node_id.branch_root_node_id,
                actual_branch_root: self.root_id,
            })
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    #[error(transparent)]
    PrimitivesError(#[from] primitives::Error),
    #[error("Index tree utils error: {0}")]
    IndexTreeUtilsError(#[from] indextree_utils::Error),
    #[error("Item id {item_id} doesn't correspond to any root node")]
    ItemIdDoesntCorrespondToRoot { item_id: String },
    #[error("Root node {0} has a parent")]
    RootWithParent(NodeId),
    #[error("Non-root node {0} has no parent")]
    NonRootWithoutParent(NodeId),
    #[error("Node {node_id} belongs to the branch at {nodes_branch_root} but this branch is at {actual_branch_root}")]
    NodeNotInBranch {
        node_id: NodeId,
        nodes_branch_root: NodeId,
        actual_branch_root: NodeId,
    },
}

fn ensure_node_in_arena<T, F>(arena: &Arena<T, F>, node_id: NodeId) -> Result<(), Error>
where
    T: DataItem,
    F: Flavor,
{
    arena.get_existing(node_id)?;
    Ok(())
}

// Ensure that the root is present in the arena and is an actual root, i.e. a node without a parent.
fn ensure_is_root<T, F>(arena: &Arena<T, F>, node_id: NodeId) -> Result<(), Error>
where
    T: DataItem,
    F: Flavor,
{
    ensure!(
        arena.get_existing(node_id)?.parent().is_none(),
        Error::RootWithParent(node_id)
    );

    Ok(())
}

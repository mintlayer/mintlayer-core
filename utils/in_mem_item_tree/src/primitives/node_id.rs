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

use super::{arena::Arena, detail::ensure_parent_child, DataItem, Error, Flavor};

/// The wrapper for `indextree::NodeId`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
pub struct NodeId(pub(super) indextree::NodeId);

impl NodeId {
    /// Return true if the corresponding node is removed.
    pub fn is_removed<T, F>(self, arena: &Arena<T, F>) -> bool
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.is_removed(&arena.arena)
    }

    /// Returns an iterator of IDs of this node and its ancestors.
    ///
    /// Use `.skip(1)` or call `.next()` once on the iterator to skip the node itself.
    ///
    /// See [indextree::NodeId::ancestors](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.ancestors).
    pub fn ancestors<T, F>(self, arena: &Arena<T, F>) -> impl Iterator<Item = NodeId> + '_
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.ancestors(&arena.arena).map(NodeId)
    }

    /// Returns an iterator of IDs of this node and its predecessors (i.e. the node, then its
    /// preceding siblings, then its ancestor, then ancestor's preceding siblings etc).
    ///
    /// Use .skip(1) or call .next() once on the iterator to skip the node itself.
    ///
    /// See [indextree::NodeId::predecessors](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.predecessors).
    pub fn predecessors<T, F>(self, arena: &Arena<T, F>) -> impl Iterator<Item = NodeId> + '_
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.predecessors(&arena.arena).map(NodeId)
    }

    /// Returns an iterator of IDs of this node and the siblings before it.
    ///
    /// Use .skip(1) or call .next() once on the iterator to skip the node itself.
    ///
    /// See [indextree::NodeId::preceding_siblings](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.preceding_siblings).
    pub fn preceding_siblings<T, F>(self, arena: &Arena<T, F>) -> impl Iterator<Item = NodeId> + '_
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.preceding_siblings(&arena.arena).map(NodeId)
    }

    /// Returns an iterator of IDs of this node and the siblings after it.
    ///
    /// Use .skip(1) or call .next() once on the iterator to skip the node itself.
    ///
    /// See [indextree::NodeId::following_siblings](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.following_siblings).
    pub fn following_siblings<T, F>(self, arena: &Arena<T, F>) -> impl Iterator<Item = NodeId> + '_
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.following_siblings(&arena.arena).map(NodeId)
    }

    /// Returns an iterator of IDs of this node's children.
    ///
    /// See [indextree::NodeId::children](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.children).
    pub fn children<T, F>(self, arena: &Arena<T, F>) -> impl Iterator<Item = NodeId> + '_
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.children(&arena.arena).map(NodeId)
    }

    /// Returns an iterator of IDs of this node's children, in reverse order.
    ///
    /// See [indextree::NodeId::reverse_children](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.reverse_children).
    pub fn reverse_children<T, F>(self, arena: &Arena<T, F>) -> impl Iterator<Item = NodeId> + '_
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.reverse_children(&arena.arena).map(NodeId)
    }

    /// An iterator of the IDs of a given node and its descendants, as a pre-order depth-first search where children are visited in insertion order.
    ///
    /// Parent nodes appear before the descendants. Use .skip(1) or call .next() once on the iterator to skip the node itself.
    ///
    /// See [indextree::NodeId::descendants](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.descendants).
    pub fn descendants<T, F>(self, arena: &Arena<T, F>) -> impl Iterator<Item = NodeId> + '_
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.descendants(&arena.arena).map(NodeId)
    }

    /// Detaches a node from its parent.
    pub fn detach_from_parent<T, F>(self, arena: &mut Arena<T, F>) -> Result<(), Error>
    where
        T: DataItem,
        F: Flavor,
    {
        self.0.detach(&mut arena.arena);
        Ok(())
    }

    /// Appends a new child to this node, after existing children.
    pub fn append_child<T, F>(self, new_child: NodeId, arena: &mut Arena<T, F>) -> Result<(), Error>
    where
        T: DataItem,
        F: Flavor,
    {
        ensure_parent_child(self, new_child, &*arena)?;
        self.0.checked_append(new_child.0, &mut arena.arena)?;
        Ok(())
    }

    /// Prepends a new child to this node, before existing children.
    pub fn prepend_child<T, F>(
        self,
        new_child: NodeId,
        arena: &mut Arena<T, F>,
    ) -> Result<(), Error>
    where
        T: DataItem,
        F: Flavor,
    {
        ensure_parent_child(self, new_child, &*arena)?;
        self.0.checked_prepend(new_child.0, &mut arena.arena)?;
        Ok(())
    }

    /// Removes a node and its descendants from the arena.
    ///
    /// See [indextree::NodeId::remove_subtree](https://docs.rs/indextree/latest/indextree/struct.NodeId.html#method.remove_subtree).
    pub fn remove_subtree<T, F>(self, arena: &mut Arena<T, F>) -> Result<(), Error>
    where
        T: DataItem,
        F: Flavor,
    {
        // Ensure the node exists in the arena, otherwise `on_subtree_removal` may panic.
        arena.get_existing(self)?;

        arena.on_subtree_removal(self);
        self.0.remove_subtree(&mut arena.arena);
        Ok(())
    }
}

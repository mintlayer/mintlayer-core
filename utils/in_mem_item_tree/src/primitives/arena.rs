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

use utils::debug_panic_or_log;

use super::{
    detail::{ItemIdMapHolder, ModificationObserver},
    node_id::NodeId,
    node_ref::{NodeMut, NodeRef},
    DataItem, Error, Flavor,
};

/// The wrapper for `indextree::Arena`.
#[derive(Clone, Debug)]
pub struct Arena<T: DataItem, F: Flavor> {
    pub(super) arena: indextree::Arena<T>,
    pub(super) modification_observer: F::ModificationObserver<T>,
    pub(super) id_classifier: <T as DataItem>::IdClassifier,
}

impl<T: DataItem, F: Flavor> Arena<T, F> {
    /// Creates a new empty `Arena`.
    pub fn new(id_classifier: <T as DataItem>::IdClassifier) -> Self
    where
        F::ModificationObserver<T>: Default,
    {
        Self {
            arena: indextree::Arena::new(),
            modification_observer: Default::default(),
            id_classifier,
        }
    }

    /// Creates a new empty Arena with enough capacity to store `n` nodes.
    pub fn with_capacity(n: usize, id_classifier: <T as DataItem>::IdClassifier) -> Self
    where
        F::ModificationObserver<T>: Default,
    {
        Self {
            arena: indextree::Arena::with_capacity(n),
            modification_observer: Default::default(),
            id_classifier,
        }
    }

    /// Returns the number of nodes the arena can hold without reallocating.
    pub fn capacity(&self) -> usize {
        self.arena.capacity()
    }

    /// Reserves capacity for `additional` more nodes to be inserted.
    pub fn reserve(&mut self, additional: usize) {
        self.arena.reserve(additional);
    }

    /// Retrieves the `NodeId` corresponding to a node in the `Arena`.
    pub fn get_node_id(&self, node: NodeRef<'_, T>) -> Option<NodeId> {
        self.arena.get_node_id(node.0).map(NodeId)
    }

    /// Creates a new node from its associated data.
    ///
    /// Note that this will re-use a previously removed node, if any.
    pub fn new_node(&mut self, data: T) -> Result<NodeId, Error> {
        let item_id = *data.item_id();
        let node_id = NodeId(self.arena.new_node(data));
        match self.modification_observer.on_node_added(node_id, item_id) {
            Ok(()) => Ok(node_id),
            Err(err) => {
                // Remove the newly created node to prevent inconsistency between the observer and the arena.
                node_id.0.remove(&mut self.arena);
                Err(err)
            }
        }
    }

    /// Returns the number of nodes in the arena, including the removed ones.
    pub fn count(&self) -> usize {
        self.arena.count()
    }

    /// Equivalent to `self.count() == 0`.
    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    /// Returns a reference to the node with the given id or None if it's not in the arena.
    ///
    /// Note: unlike the wrapped `indextree`'s function, we don't return removed nodes here
    /// (if we allowed this, `NodeRef`/`NodeMut`'s `get` methods would panic if called on
    /// a removed node).
    pub fn get(&self, id: NodeId) -> Option<NodeRef<'_, T>> {
        self.arena.get(id.0).filter(|node| !node.is_removed()).map(NodeRef)
    }

    /// Returns a reference to the node with the given id or an error if it's not in the arena.
    ///
    /// Same as in `get`, removed nodes are never returned.
    pub fn get_existing(&self, id: NodeId) -> Result<NodeRef<'_, T>, Error> {
        let node = self.arena.get(id.0).ok_or(Error::NodeIdNotInArena(id))?;
        if node.is_removed() {
            Err(Error::NodeIsRemoved(id))
        } else {
            Ok(NodeRef(node))
        }
    }

    /// Returns a mutable reference to the node with the given id or None if it's not in the arena.
    ///
    /// Same as in `get`, removed nodes are never returned.
    pub fn get_mut(&mut self, id: NodeId) -> Option<NodeMut<'_, T>> {
        self.arena.get_mut(id.0).filter(|node| !node.is_removed()).map(NodeMut)
    }

    /// Returns a mutable reference to the node with the given id or an error if it's not in the arena.
    ///
    /// Same as in `get`, removed nodes are never returned.
    pub fn get_existing_mut(&mut self, id: NodeId) -> Result<NodeMut<'_, T>, Error> {
        let node = self.arena.get_mut(id.0).ok_or(Error::NodeIdNotInArena(id))?;
        if node.is_removed() {
            Err(Error::NodeIsRemoved(id))
        } else {
            Ok(NodeMut(node))
        }
    }

    // Note: we don't expose `indextree::Arena::iter` and `iter_mut`, which iterate over all
    // nodes in the arena, including the removed ones. If we decide to expose them in the future,
    // we'll have to either filter out removed nodes or modify the interface of `NodeRef`/`NodeMut`
    // (so that e.g. the "get" methods return an `Option`, where `Some` corresponds to
    // an existing node and `None` to a removed one).

    /// Clears all the nodes in the arena, but retains its allocated capacity.
    ///
    /// Note that this does not marks all nodes as removed, but completely removes them from
    /// the arena storage, thus invalidating all the node ids that were previously created.
    pub fn clear(&mut self) {
        self.arena.clear();
        self.modification_observer.on_whole_arena_cleared();
    }

    /// Returns a node id given a item id. The availability of this method depends on the arena's
    /// `Flavor`.
    pub fn node_id_by_item_id(&self, item_id: &<T as DataItem>::Id) -> Option<NodeId>
    where
        F::ModificationObserver<T>: ItemIdMapHolder<T>,
    {
        self.modification_observer.item_id_map().get(item_id).copied()
    }

    // Note: this must be called before the subtree has been removed.
    pub(super) fn on_subtree_removal(&mut self, node_id: NodeId) {
        for descendant_id in node_id.0.descendants(&self.arena) {
            if let Some(node) = self.arena.get(descendant_id) {
                self.modification_observer.on_node_removed(node.get().item_id());
            } else {
                debug_panic_or_log!("node id {descendant_id} isn't in the arena");
            }
        }
    }
}

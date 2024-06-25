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

//! Wrappers for `indextree` primitives intended to represent a tree of items that already
//! have a parent-child relationship.
//! The following guarantees are provided:
//! 1) If two tree nodes are a parent and a child, then the corresponding items must also
//! be a parent and a child. Note that the opposite is not true - you are allowed to have
//! a parent and child items whose corresponding tree nodes are not connected.
//! 2) For each item id there can be at most one node in the arena corresponding to it.
//! Since this guarantee requires the additional overhead of maintaining the item-id-to-node-id
//! map, the user has the option of enforcing it in debug builds only; this is controlled via
//! one of the generic parameters of `Arena`.

mod arena;
mod detail;
mod node_id;
mod node_ref;

pub mod indextree_utils;

use std::fmt::{Debug, Display};

pub use arena::Arena;
pub use detail::{ItemIdMapHolder, TmpError};
pub use node_id::NodeId;
pub use node_ref::{NodeMut, NodeRef};

/// This represents the node's data item.
/// Note: the code in this module relies on the fact that the returned ids will never change.
/// So, implementors of this trait should avoid having mutators for the corresponding fields
/// (or be extra-careful about accidental mutations).
pub trait DataItem {
    type Id: Clone + Copy + Debug + Display + Ord;

    /// Some kind of external object that might be needed by `DataItem`'s implementor to be able
    /// to produce `Option<&Id>` in `parent_item_id`. E.g. chainstate's `BlockIndex` references its
    /// parent simply as `Id<GenBlock>`; in order to check whether it's the genesis, one needs access
    /// to `ChainConfig`, which the classifier may hold in this case.
    type IdClassifier: Clone + Debug;

    /// Return the id of the item itself.
    fn item_id(&self) -> &Self::Id;

    /// Return the id of the items's parent or `None` if the item has no parent.
    /// Note that the exact meaning of `None` may differ depending on the implementor. E.g. if it's
    /// the chainstate's `GenBlockIndex`, then the tree may contain the genesis itself, so having
    /// `None` as the parent will mean that this node is the genesis. If it's `BlockIndex`, then
    /// the tree may not contain the genesis, so having `None` as the parent will mean that this
    /// node's parent is the genesis.
    fn parent_item_id(&self, id_classifier: &Self::IdClassifier) -> Option<&Self::Id>;
}

/// The "flavor" that is used as a generic parameter for the `Arena`.
pub trait Flavor {
    /// The modification observer, which is informed about nodes' additions and removals.
    type ModificationObserver<T: DataItem>: detail::ModificationObserver<T>;
}

/// The favor that maintains the item-id-to-node-id map in both debug and release builds.
pub struct WithItemIdToNodeIdMap;

impl Flavor for WithItemIdToNodeIdMap {
    type ModificationObserver<T: DataItem> = detail::TrackingModificationObserver<T>;
}

/// The favor that maintains the item-id-to-node-id map only in debug builds.
pub struct WithDebugOnlyChecks;

impl Flavor for WithDebugOnlyChecks {
    type ModificationObserver<T: DataItem> = detail::DebugOnlyTrackingModificationObserver<T>;
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    // Note: `indextree::NodeError` doesn't implement Eq/PartialEq, so we store a string instead.
    #[error("Index tree error: {0}")]
    IndexTreeError(String),
    #[error("Index tree utils error: {0}")]
    IndexTreeUtilsError(#[from] indextree_utils::Error),
    #[error("Node id {0} is not in arena")]
    NodeIdNotInArena(NodeId),
    #[error("Node id {0} is removed")]
    NodeIsRemoved(NodeId),
    #[error(
        "Item {child_item_id} has parent {childs_parent_item_id} instead of expected {expected_parent_item_id}",
    )]
    NotParentChild {
        child_item_id: String,
        childs_parent_item_id: String,
        expected_parent_item_id: String,
    },
    #[error("Item id {item_id} is already in the arena")]
    ItemAlreadyInArena { item_id: String },
}

impl From<indextree::NodeError> for Error {
    fn from(err: indextree::NodeError) -> Self {
        Error::IndexTreeError(err.to_string())
    }
}

pub fn for_all_nodes_depth_first<T, F, E>(
    arena: &Arena<T, F>,
    root_id: NodeId,
    mut handler: impl FnMut(NodeId) -> Result<bool, E>,
) -> Result<(), E>
where
    T: DataItem,
    F: Flavor,
    E: std::error::Error + From<Error>,
{
    indextree_utils::for_all_nodes_depth_first(
        &arena.arena,
        root_id.0,
        |node_id| -> Result<_, TmpError<E, indextree_utils::Error>> {
            handler(NodeId(node_id)).map_err(TmpError::OuterError)
        },
    )
    .map_err(|err| err.into_outer_error_via::<Error>())
}

#[cfg(test)]
mod tests;

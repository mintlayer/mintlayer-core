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

use std::collections::BTreeMap;

use utils::{debug_assert_or_log, displayable_option::DisplayableOption, ensure};

use super::{arena::Arena, node_id::NodeId, DataItem, Error, Flavor};

/// The trait that is referenced by the `Flavor` trait. `Arena` holds an instance of such
/// an observer and notifies it about the corresponding modifications.
pub trait ModificationObserver<T: DataItem>: Clone + std::fmt::Debug + Default {
    fn on_node_added(&mut self, node_id: NodeId, item_id: <T as DataItem>::Id)
        -> Result<(), Error>;
    fn on_node_removed(&mut self, item_id: &<T as DataItem>::Id);
    fn on_whole_arena_cleared(&mut self);
}

/// `Arena` uses this trait to get access to the item-id-to-node-id map that is held within
///  the observer, if any.
pub trait ItemIdMapHolder<T: DataItem> {
    fn item_id_map(&self) -> &BTreeMap<<T as DataItem>::Id, NodeId>;
}

/// This is the observer that always holds the item-id-to-node-id map, which allows `Arena`
/// to implement some extra methods.
pub struct TrackingModificationObserver<T: DataItem>(BTreeMap<<T as DataItem>::Id, NodeId>);

impl<T: DataItem> ModificationObserver<T> for TrackingModificationObserver<T> {
    fn on_node_added(
        &mut self,
        node_id: NodeId,
        item_id: <T as DataItem>::Id,
    ) -> Result<(), Error> {
        use std::collections::btree_map::Entry;

        match self.0.entry(item_id) {
            Entry::Vacant(e) => {
                e.insert(node_id);
                Ok(())
            }
            Entry::Occupied(_) => Err(Error::ItemAlreadyInArena {
                item_id: item_id.to_string(),
            }),
        }
    }

    fn on_node_removed(&mut self, item_id: &<T as DataItem>::Id) {
        let removed = self.0.remove(item_id).is_some();
        debug_assert_or_log!(removed, "item id {item_id} wasn't in the map");
    }

    fn on_whole_arena_cleared(&mut self) {
        self.0.clear();
    }
}

// Implement Default/Debug/Clone by hand, because `derive` would automatically add the corresponding
// trait bounds for T, which we don't need.
impl<T: DataItem> Default for TrackingModificationObserver<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}
impl<T: DataItem> std::fmt::Debug for TrackingModificationObserver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TrackingModificationObserver").field(&self.0).finish()
    }
}
impl<T: DataItem> Clone for TrackingModificationObserver<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: DataItem> ItemIdMapHolder<T> for TrackingModificationObserver<T> {
    fn item_id_map(&self) -> &BTreeMap<<T as DataItem>::Id, NodeId> {
        &self.0
    }
}

/// This is the observer that only holds the item-id-to-node-id map in debug builds, to perform
/// the corresponding runtime checks.
pub struct DebugOnlyTrackingModificationObserver<T: DataItem> {
    #[cfg(debug_assertions)]
    inner: TrackingModificationObserver<T>,
    #[cfg(not(debug_assertions))]
    inner: std::marker::PhantomData<T>,
}

impl<T: DataItem> DebugOnlyTrackingModificationObserver<T> {
    #[cfg(all(test, debug_assertions))]
    pub fn inner(&self) -> &TrackingModificationObserver<T> {
        &self.inner
    }
}

impl<T: DataItem> ModificationObserver<T> for DebugOnlyTrackingModificationObserver<T> {
    fn on_node_added(
        &mut self,
        node_id: NodeId,
        item_id: <T as DataItem>::Id,
    ) -> Result<(), Error> {
        #[cfg(debug_assertions)]
        {
            self.inner.on_node_added(node_id, item_id)
        }
        #[cfg(not(debug_assertions))]
        {
            Ok(())
        }
    }

    fn on_node_removed(&mut self, item_id: &<T as DataItem>::Id) {
        #[cfg(debug_assertions)]
        {
            self.inner.on_node_removed(item_id);
        }
    }

    fn on_whole_arena_cleared(&mut self) {
        #[cfg(debug_assertions)]
        {
            self.inner.on_whole_arena_cleared();
        }
    }
}

// Implement Default/Debug/Clone by hand, because `derive` would automatically add the corresponding
// trait bounds for T, which we don't need.
impl<T: DataItem> Default for DebugOnlyTrackingModificationObserver<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}
impl<T: DataItem> std::fmt::Debug for DebugOnlyTrackingModificationObserver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DebugOnlyTrackingModificationObserver")
            .field(&self.inner)
            .finish()
    }
}
impl<T: DataItem> Clone for DebugOnlyTrackingModificationObserver<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// A temporary error type, for use in the following scenario:
/// You have a utility module with a function that tries to be error-agnostic and that accepts a callback:
/// ```ignore
///     enum MyModuleErrorType { ... }
///
///     fn func<E>(callback: Fn(X) -> Result<Y, E>) -> Result<(), E>
///     where
///         E: Error + From<MyModuleErrorType> { ...
/// ```
/// The intent is that you want the caller to be able to return its own higher-level error type
/// from the callback, which will then be propagated out of the function; the function itself,
/// on the other hand,  may produce errors from `MyModuleErrorType`, which will be converted
/// to `E` via `From`.
///
/// Then, in another module you need a function that wraps the previous one:
/// ```ignore
///     enum WrapperModuleErrorType { InnerError(#[from] MyModuleErrorType), ... }
///
///     fn wrapper_func<E>(callback: Fn(X) -> Result<Y, E>) -> Result<(), E>
///     where
///         E: Error + From<WrapperModuleErrorType> { // call `func` somehow
/// ```
/// Unfortunately, the above won't work unless you require that `E` implements `From<MyModuleErrorType>`.
/// If this is not what you want, you may use `TmpError` as a temporary error holder:
/// ```ignore
///     fn wrapper_func<E>(callback: Fn(X) -> Result<Y, E>) -> Result<(), E>
///     where
///         E: Error + From<WrapperModuleErrorType>
///     {
///         func(|xxx| -> Result<_, TmpError<E, MyModuleErrorType>> {
///             callback(xxx).map_err(TmpError::OuterError)
///         })
///         .map_err(|err| err.into_outer_error_via::<WrapperModuleErrorType>())
///     }
/// ```
// TODO move it elsewhere
#[derive(thiserror::Error, Debug)]
pub enum TmpError<OuterError, InnerError>
where
    OuterError: std::error::Error,
    InnerError: std::error::Error,
{
    #[error(transparent)]
    OuterError(OuterError),
    #[error(transparent)]
    InnerError(#[from] InnerError),
}

impl<OuterError, InnerError> TmpError<OuterError, InnerError>
where
    OuterError: std::error::Error,
    InnerError: std::error::Error,
{
    pub fn into_outer_error_via<IntermediateError>(self) -> OuterError
    where
        OuterError: From<IntermediateError>,
        IntermediateError: From<InnerError>,
    {
        match self {
            TmpError::OuterError(err) => err,
            TmpError::InnerError(err) => {
                let interm_err: IntermediateError = err.into();
                interm_err.into()
            }
        }
    }
}

pub fn ensure_parent_child_items<T: DataItem>(
    parent: &T,
    child: &T,
    id_classifier: &<T as DataItem>::IdClassifier,
) -> Result<(), Error> {
    let childs_parent_item_id = child.parent_item_id(id_classifier);
    ensure!(
        childs_parent_item_id.is_some_and(|parent_id| parent_id == parent.item_id()),
        Error::NotParentChild {
            child_item_id: child.item_id().to_string(),
            childs_parent_item_id: childs_parent_item_id.as_displayable().to_string(),
            expected_parent_item_id: parent.item_id().to_string()
        }
    );
    Ok(())
}

pub fn ensure_parent_child<T, F>(
    parent_id: NodeId,
    child_id: NodeId,
    arena: &Arena<T, F>,
) -> Result<(), Error>
where
    T: DataItem,
    F: Flavor,
{
    let parent_node = arena.get_existing(parent_id)?;
    let child_node = arena.get_existing(child_id)?;
    ensure_parent_child_items(parent_node.get(), child_node.get(), &arena.id_classifier)
}

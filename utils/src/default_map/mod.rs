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

use std::{
    borrow::{Borrow, Cow},
    collections::{btree_map, BTreeMap},
};

/// Like [std::collections::BTreeMap] but "empty" entries contain given default value.
///
/// While the normal `BTreeMap` can be considered analogous to a partial function
/// `fn(K) -> Option<V>`, `DefaultMap` is analogous to the total function `fn(K) -> V`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct DefaultMap<K, V> {
    map: BTreeMap<K, V>,
    default: V,
}

impl<K, V: Default> DefaultMap<K, V> {
    /// New [DefaultMap], the default value determined by the [Default] trait
    pub fn new() -> Self {
        Self::default()
    }
}

impl<K, V> DefaultMap<K, V> {
    /// New [DefaultMap] with specified default value
    pub fn with_custom_default(default: V) -> Self {
        Self {
            map: BTreeMap::new(),
            default,
        }
    }

    /// Reset all items to the default value
    pub fn clear(&mut self) {
        self.map.clear()
    }
}

impl<K, V: Default> Default for DefaultMap<K, V> {
    fn default() -> Self {
        Self::with_custom_default(V::default())
    }
}

impl<K: Ord, V: Eq + Default + Clone> FromIterator<(K, V)> for DefaultMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut this = Self::new();
        for (k, v) in iter {
            this.set(k, v);
        }
        this
    }
}

impl<K: Ord, V> DefaultMap<K, V> {
    /// Get value associated with given key
    pub fn get<Q: Ord + ?Sized>(&self, key: &Q) -> &V
    where
        K: Borrow<Q>,
    {
        self.map.get(key).unwrap_or(&self.default)
    }
}

impl<K: Ord, V: Eq + Clone> DefaultMap<K, V> {
    /// Set value associated with given key.
    pub fn set(&mut self, key: K, value: V) -> Cow<'_, V> {
        match self.map.entry(key) {
            btree_map::Entry::Vacant(entry) => {
                if value != self.default {
                    entry.insert(value);
                }
                Cow::Borrowed(&self.default)
            }
            btree_map::Entry::Occupied(mut entry) => {
                let prev = if value != self.default {
                    entry.insert(value)
                } else {
                    entry.remove()
                };
                Cow::Owned(prev)
            }
        }
    }

    /// Reset the value at given key to the default value, return the original value.
    pub fn reset<Q: Ord + ?Sized>(&mut self, key: &Q) -> Cow<'_, V>
    where
        K: Borrow<Q>,
    {
        self.map.remove(key).map_or_else(|| Cow::Borrowed(&self.default), Cow::Owned)
    }

    /// Get mutable access to given key entry
    pub fn get_mut(&mut self, key: K) -> ValueMut<'_, K, V> {
        let entry = match self.map.entry(key) {
            btree_map::Entry::Vacant(entry) => ValueMutEntry::Vacant(self.default.clone(), entry),
            btree_map::Entry::Occupied(entry) => ValueMutEntry::Occupied(entry),
        };
        let default = &self.default;
        ValueMut { entry, default }
    }
}

/// A smart pointer representing a mutable reference to a value in the map.
pub struct ValueMut<'a, K: Ord, V: Eq> {
    entry: ValueMutEntry<'a, K, V>,
    default: &'a V,
}

enum ValueMutEntry<'a, K, V> {
    Vacant(V, btree_map::VacantEntry<'a, K, V>),
    Occupied(btree_map::OccupiedEntry<'a, K, V>),
    Dropped,
}

impl<K: Ord, V: Eq> std::ops::Deref for ValueMut<'_, K, V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        match &self.entry {
            ValueMutEntry::Vacant(val, _entry) => &val,
            ValueMutEntry::Occupied(entry) => entry.get(),
            ValueMutEntry::Dropped => panic!("Not dropped"),
        }
    }
}

impl<K: Ord, V: Eq> std::ops::DerefMut for ValueMut<'_, K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.entry {
            ValueMutEntry::Vacant(ref mut val, ref _entry) => val,
            ValueMutEntry::Occupied(ref mut entry) => entry.get_mut(),
            ValueMutEntry::Dropped => panic!("Not dropped"),
        }
    }
}

impl<K: Ord, V: Eq> Drop for ValueMut<'_, K, V> {
    fn drop(&mut self) {
        match std::mem::replace(&mut self.entry, ValueMutEntry::Dropped) {
            ValueMutEntry::Vacant(val, entry) => {
                if &val != self.default {
                    let _ = entry.insert(val);
                }
            }
            ValueMutEntry::Occupied(entry) => {
                if entry.get() == self.default {
                    let _ = entry.remove();
                }
            }
            ValueMutEntry::Dropped => (),
        }
    }
}

#[cfg(test)]
mod test;

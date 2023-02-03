// Copyright (c) 2022 RBB S.r.l
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

//! A dead-simple reference implementation of some aspects of a storage backend

use storage_core::{backend, Data, MapIndex};

/// A modifying action to apply to a backend or a model
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WriteAction {
    /// Write data
    Put(Data, Data),
    /// Delete data
    Del(Data),
}

impl WriteAction {
    /// Apply given function to the key
    pub fn map_key(self, f: impl FnOnce(Data) -> Data) -> Self {
        match self {
            Self::Put(k, v) => Self::Put(f(k), v),
            Self::Del(k) => Self::Del(f(k)),
        }
    }
}

pub trait ApplyActions {
    /// Apply a sequence of actions to a transaction
    fn apply_actions(&mut self, idx: MapIndex, iter: impl Iterator<Item = WriteAction>) {
        iter.for_each(|act| self.apply_action(idx, act));
    }

    /// Apply one action to a transaction
    fn apply_action(&mut self, idx: MapIndex, action: WriteAction);
}

impl<T: backend::WriteOps> ApplyActions for T {
    fn apply_action(&mut self, idx: MapIndex, action: WriteAction) {
        match action {
            WriteAction::Put(key, val) => self.put(idx, key, val).expect("put to succeed"),
            WriteAction::Del(key) => self.del(idx, key.as_ref()).expect("del to succeed"),
        }
    }
}

/// Reference implementation of single database map
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Model(std::collections::BTreeMap<Data, Data>);

impl Model {
    /// New empty map
    pub fn new() -> Self {
        Self::default()
    }

    /// New model pre-populated by contents resulting by applying a sequence of actions
    pub fn from_actions<T: IntoIterator<Item = WriteAction>>(iter: T) -> Self {
        let mut this = Self::default();
        this.extend(iter);
        this
    }

    /// New model obtained by dumping a database
    pub fn from_db<B: backend::BackendImpl>(storage: &B, idx: MapIndex) -> Self {
        let dbtx = storage.transaction_ro().unwrap();
        Self::from_tx(&dbtx, idx)
    }

    /// New model obtained by dumping a database in a transaction. May contain uncommitted changes.
    pub fn from_tx<Tx: for<'tx> backend::PrefixIter<'tx>>(tx: &Tx, idx: MapIndex) -> Self {
        Model(backend::PrefixIter::prefix_iter(tx, idx, Data::new()).unwrap().collect())
    }

    /// Get the inner map
    pub fn inner(&self) -> &std::collections::BTreeMap<Data, Data> {
        &self.0
    }

    /// Take the inner map
    pub fn into_inner(self) -> std::collections::BTreeMap<Data, Data> {
        self.0
    }

    /// Apply given action
    pub fn apply_action(&mut self, action: WriteAction) {
        match action {
            WriteAction::Put(key, val) => {
                let _ = self.0.insert(key, val);
            }
            WriteAction::Del(key) => {
                let _ = self.0.remove(&key);
            }
        }
    }

    /// Apply a sequence of actions
    pub fn apply_actions(&mut self, iter: impl Iterator<Item = WriteAction>) {
        self.extend(iter)
    }

    /// Get value associated with given key
    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<&[u8]> {
        self.0.get(key.as_ref()).map(|v| v.as_ref())
    }

    /// Iterator over key-value pairs
    pub fn iter(&self) -> impl '_ + Iterator<Item = (&[u8], &[u8])> {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.as_ref()))
    }
}

impl IntoIterator for Model {
    type Item = (Data, Data);
    type IntoIter = std::collections::btree_map::IntoIter<Data, Data>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Extend<WriteAction> for Model {
    fn extend<T: IntoIterator<Item = WriteAction>>(&mut self, iter: T) {
        iter.into_iter().for_each(|action| self.apply_action(action))
    }
}

impl FromIterator<(Data, Data)> for Model {
    fn from_iter<T: IntoIterator<Item = (Data, Data)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

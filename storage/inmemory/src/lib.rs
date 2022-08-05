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

use common::sync;
use std::collections::BTreeMap;
use storage_core::{
    schema::{self, Schema},
    traits, transaction, Data,
};

// These store the data
type StoreMapSingle = BTreeMap<Data, Data>;
type StoreMapMulti = BTreeMap<Data, Vec<Data>>;

pub enum StoreMap {
    Single(StoreMapSingle),
    Multi(StoreMapMulti),
}

// Set of store maps, one per db index.
type StoreMapSet = BTreeMap<&'static str, StoreMap>;

// These store changes to the data that could be commited or discarded
type DeltaMapSingle = BTreeMap<Data, Option<Data>>;

// Vector delta
#[allow(unused)]
enum VecDelta<T> {
    Set(Vec<T>),
    Modify { add: Vec<T>, del: Vec<T> },
}

type DeltaMapMulti = BTreeMap<Data, VecDelta<Data>>;

enum DeltaMap {
    Single(DeltaMapSingle),
    Multi(DeltaMapMulti),
}

// Set of delta maps, one per db index.
type DeltaMapSet = BTreeMap<&'static str, DeltaMap>;

impl DeltaMap {
    // Apply given delta to the store map
    fn apply_to(self, store: &mut StoreMap) {
        match (self, store) {
            (DeltaMap::Single(delta), StoreMap::Single(store)) => {
                delta.into_iter().for_each(|(key, val)| {
                    match val {
                        Some(val) => store.insert(key, val),
                        None => store.remove(&key),
                    };
                })
            }
            (DeltaMap::Multi(_delta), StoreMap::Multi(_store)) => {
                todo!("Key-multivalue map not implemented")
            }
            _ => unreachable!("Map type mismatch"),
        }
    }
}

/// Store is a collection of key-(multi)value maps
pub struct Store<Sch: Schema> {
    maps: sync::Arc<sync::RwLock<StoreMapSet>>,
    _phantom: std::marker::PhantomData<fn() -> Sch>,
}

impl<Sch: Schema> Clone for Store<Sch> {
    fn clone(&self) -> Self {
        Self {
            maps: sync::Arc::clone(&self.maps),
            _phantom: Default::default(),
        }
    }
}

impl<Sch: 'static + Schema> traits::Backend<Sch> for Store<Sch> {}

pub trait InitStore: Schema {
    fn init() -> BTreeMap<&'static str, StoreMap>;
}

impl InitStore for () {
    fn init() -> BTreeMap<&'static str, StoreMap> {
        BTreeMap::new()
    }
}

impl<DBIdx: schema::DBIndex, Rest: InitStore> InitStore for (DBIdx, Rest) {
    fn init() -> BTreeMap<&'static str, StoreMap> {
        let mut map = Rest::init();
        // TODO support multi
        let orig = map.insert(DBIdx::NAME, StoreMap::Single(BTreeMap::new()));
        assert!(orig.is_none(), "DB index names are not unique");
        map
    }
}

impl<Sch: InitStore> Store<Sch> {
    /// New empty store
    pub fn new() -> Self {
        Self {
            maps: sync::Arc::new(sync::RwLock::new(Sch::init())),
            _phantom: Default::default(),
        }
    }
}

impl<'tx, Sch: 'static + Schema> traits::Transactional<'tx, Sch> for Store<Sch> {
    type TransactionRo = TransactionRo<'tx, Sch>;
    type TransactionRw = TransactionRw<'tx, Sch>;

    fn transaction_ro<'st: 'tx>(&'st self) -> Self::TransactionRo {
        TransactionRo::start(self)
    }

    fn transaction_rw<'st: 'tx>(&'st self) -> Self::TransactionRw {
        TransactionRw::start(self)
    }
}

impl<Sch: InitStore> Default for Store<Sch> {
    fn default() -> Self {
        Self::new()
    }
}

/// Store read-only transaction.
pub struct TransactionRo<'st, Sch> {
    store: sync::RwLockReadGuard<'st, StoreMapSet>,
    _phantom: std::marker::PhantomData<fn() -> Sch>,
}

impl<'st, Sch: Schema> TransactionRo<'st, Sch> {
    // Start a transaction on given store
    fn start(store: &'st Store<Sch>) -> Self {
        let store = store.maps.read().expect("Mutex locked by a crashed thread");
        Self {
            store,
            _phantom: Default::default(),
        }
    }
}

impl<'st, 'm, Sch: Schema> traits::GetMapRef<'m, Sch> for TransactionRo<'st, Sch> {
    type MapRef = SingleMapView<'m>;

    fn get<'tx: 'm, DBIdx: schema::DBIndex, I>(&'tx self) -> Self::MapRef {
        if let Some(StoreMap::Single(store)) = self.store.get(DBIdx::NAME) {
            SingleMapView::new(store)
        } else {
            panic!("Unexpected map kind")
        }
    }
}

/// Store read/write transaction.
///
/// Contains a pointer to the original store and a set of changes to it. If the transaction is
/// commited, the changes are flushed to the store. If the transaction is aborted, the changes are
/// discarded.
pub struct TransactionRw<'st, Sch: Schema> {
    store: sync::RwLockWriteGuard<'st, StoreMapSet>,
    delta: DeltaMapSet,
    _phantom: std::marker::PhantomData<fn() -> Sch>,
}

impl<'st, Sch: Schema> TransactionRw<'st, Sch> {
    // Start a transaction on given store
    fn start(store: &'st Store<Sch>) -> Self {
        let store = store.maps.write().expect("Mutex locked by a crashed thread");
        let delta = store
            .iter()
            .map(|(&k, v)| {
                let dm = match v {
                    StoreMap::Single(_) => DeltaMap::Single(Default::default()),
                    StoreMap::Multi(_) => DeltaMap::Multi(Default::default()),
                };
                (k, dm)
            })
            .collect();
        let _phantom = Default::default();
        Self {
            store,
            delta,
            _phantom,
        }
    }
}

impl<'st, 'm, Sch: Schema> traits::GetMapRef<'m, Sch> for TransactionRw<'st, Sch> {
    type MapRef = SingleMapRef<'m>;

    fn get<'tx: 'm, DBIdx: schema::DBIndex, I>(&'tx self) -> Self::MapRef {
        match (self.store.get(DBIdx::NAME), self.delta.get(DBIdx::NAME)) {
            (Some(StoreMap::Single(store)), Some(DeltaMap::Single(delta))) => {
                SingleMapRef::new(store, delta)
            }
            _ => panic!("Unexpected map kind"),
        }
    }
}

impl<'st, 'm, Sch: Schema> traits::GetMapMut<'m, Sch> for TransactionRw<'st, Sch> {
    type MapMut = SingleMapMut<'m>;

    fn get_mut<'tx: 'm, DBIdx: schema::DBIndex, I>(&'tx mut self) -> Self::MapMut {
        match (self.store.get(DBIdx::NAME), self.delta.get_mut(DBIdx::NAME)) {
            (Some(StoreMap::Single(store)), Some(DeltaMap::Single(delta))) => {
                SingleMapMut::new(store, delta)
            }
            _ => panic!("Unexpected map kind"),
        }
    }
}

impl<'st, Sch: Schema> transaction::TransactionRo for TransactionRo<'st, Sch> {
    type Error = storage_core::Error;

    fn finalize(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<'st, Sch: Schema> transaction::TransactionRw for TransactionRw<'st, Sch> {
    type Error = storage_core::Error;

    /// Commit a transaction
    fn commit(mut self) -> Result<(), Self::Error> {
        self.store
            .values_mut()
            .zip(self.delta.into_values())
            .for_each(|(store, delta)| {
                delta.apply_to(store);
            });
        Ok(())
    }

    /// Abort a transaction.
    fn abort(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Represents an immutable store with keys mapping to one value inside a read-only transaction.
pub struct SingleMapView<'tx>(&'tx StoreMapSingle);

impl<'tx> SingleMapView<'tx> {
    fn new(store: &'tx StoreMapSingle) -> Self {
        Self(store)
    }
}

impl traits::MapRef for SingleMapView<'_> {
    fn get(&self, key: &[u8]) -> storage_core::Result<Option<&[u8]>> {
        Ok(self.0.get(key).map(AsRef::as_ref))
    }
}

/// Represents an immutable key-value store with keys mapping to one value.
pub struct SingleMapRef<'tx> {
    store: &'tx StoreMapSingle,
    delta: &'tx DeltaMapSingle,
}

impl<'tx> SingleMapRef<'tx> {
    fn new(store: &'tx StoreMapSingle, delta: &'tx DeltaMapSingle) -> Self {
        Self { store, delta }
    }
}

impl traits::MapRef for SingleMapRef<'_> {
    fn get(&self, key: &[u8]) -> storage_core::Result<Option<&[u8]>> {
        let res = match &self.delta.get(key) {
            Some(val) => val.as_ref(),
            None => self.store.get(key),
        };
        Ok(res.map(AsRef::as_ref))
    }
}

/// Represents a mutable key-value store with keys mapping to one value.
pub struct SingleMapMut<'tx> {
    store: &'tx StoreMapSingle,
    delta: &'tx mut DeltaMapSingle,
}

impl<'tx> SingleMapMut<'tx> {
    fn new(store: &'tx StoreMapSingle, delta: &'tx mut DeltaMapSingle) -> Self {
        Self { store, delta }
    }
}

impl traits::MapRef for SingleMapMut<'_> {
    fn get(&self, key: &[u8]) -> storage_core::Result<Option<&[u8]>> {
        let res = match &self.delta.get(key) {
            Some(val) => val.as_ref(),
            None => self.store.get(key),
        };
        Ok(res.map(AsRef::as_ref))
    }
}

impl traits::MapMut for SingleMapMut<'_> {
    fn put(&mut self, key: Data, val: Data) -> storage_core::Result<()> {
        self.delta.insert(key, Some(val));
        Ok(())
    }

    fn del(&mut self, key: &[u8]) -> storage_core::Result<()> {
        self.delta.insert(key.to_vec(), None);
        Ok(())
    }
}

#[cfg(test)]
mod test;

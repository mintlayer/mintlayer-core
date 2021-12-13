use crate::schema::{self, Schema};
use crate::Data;
use common::sync;
use std::collections::BTreeMap;

// These store the data
type StoreMapSingle = BTreeMap<Data, Data>;
type StoreMapMulti = BTreeMap<Data, Vec<Data>>;

pub enum StoreMap {
    Single(StoreMapSingle),
    Multi(StoreMapMulti),
}

// Set of store maps, one per column.
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

// Set of delta maps, one per column.
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
    _phantom: std::marker::PhantomData<Sch>,
}

impl<Sch: Schema> Clone for Store<Sch> {
    fn clone(&self) -> Self {
        Self {
            maps: sync::Arc::clone(&self.maps),
            _phantom: Default::default(),
        }
    }
}

pub trait InitStore: Schema {
    fn init() -> BTreeMap<&'static str, StoreMap>;
}

impl InitStore for () {
    fn init() -> BTreeMap<&'static str, StoreMap> {
        BTreeMap::new()
    }
}

impl<Col: schema::Column, Rest: InitStore> InitStore for (Col, Rest) {
    fn init() -> BTreeMap<&'static str, StoreMap> {
        let mut map = Rest::init();
        // TODO support multi
        let orig = map.insert(Col::NAME, StoreMap::Single(BTreeMap::new()));
        assert!(orig.is_none(), "Column names are not unique");
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

impl<'st, Sch: 'static + Schema> crate::transaction::Transactional<'st> for Store<Sch> {
    type TransactionRo = TransactionRo<'st, Sch>;
    type TransactionRw = TransactionRw<'st, Sch>;

    fn start_transaction_ro(&'st self) -> Self::TransactionRo {
        TransactionRo::start(self)
    }

    fn start_transaction_rw(&'st self) -> Self::TransactionRw {
        TransactionRw::start(self)
    }
}

impl<Sch: InitStore> Default for Store<Sch> {
    fn default() -> Self {
        Self::new()
    }
}

// Read-only transaction is a read-write transaction internally for now.
// TODO: We can get some code clarity and efficiency gains by making this a separate type.
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

impl<'st, Sch: Schema> crate::traits::GetMapRef<'st, Sch> for TransactionRo<'st, Sch> {
    type MapRef = SingleMapView<'st>;

    fn get<Col: schema::Column, I>(&self) -> SingleMapView<'_> {
        if let Some(StoreMap::Single(store)) = self.store.get(Col::NAME) {
            SingleMapView::new(store)
        } else {
            panic!("Unexpected map kind")
        }
    }
}

/// Store transaction.
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

impl<'st, Sch: Schema> crate::traits::GetMapRef<'st, Sch> for TransactionRw<'st, Sch> {
    type MapRef = SingleMapRef<'st>;

    fn get<Col: schema::Column, I>(&self) -> SingleMapRef<'_> {
        match (self.store.get(Col::NAME), self.delta.get(Col::NAME)) {
            (Some(StoreMap::Single(store)), Some(DeltaMap::Single(delta))) => {
                SingleMapRef::new(store, delta)
            }
            _ => panic!("Unexpected map kind"),
        }
    }
}

impl<'tx, 'st: 'tx, Sch: Schema> crate::traits::GetMapMut<'tx, Sch> for TransactionRw<'st, Sch> {
    type MapMut = SingleMapMut<'tx>;

    fn get_mut<Col: schema::Column, I>(&'tx mut self) -> SingleMapMut<'tx> {
        match (self.store.get(Col::NAME), self.delta.get_mut(Col::NAME)) {
            (Some(StoreMap::Single(store)), Some(DeltaMap::Single(delta))) => {
                SingleMapMut::new(store, delta)
            }
            _ => panic!("Unexpected map kind"),
        }
    }
}

impl<'st, Sch: Schema> crate::transaction::TransactionRo for TransactionRo<'st, Sch> {
    type Error = crate::Error;

    fn finalize(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<'st, Sch: Schema> crate::transaction::TransactionRw for TransactionRw<'st, Sch> {
    type Error = crate::Error;

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

impl crate::traits::MapRef for SingleMapView<'_> {
    fn get(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
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

impl crate::traits::MapRef for SingleMapRef<'_> {
    fn get(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
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

impl crate::traits::MapRef for SingleMapMut<'_> {
    fn get(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
        let res = match &self.delta.get(key) {
            Some(val) => val.as_ref(),
            None => self.store.get(key),
        };
        Ok(res.map(AsRef::as_ref))
    }
}

impl crate::traits::MapMut for SingleMapMut<'_> {
    fn put(&mut self, key: Data, val: Data) -> crate::Result<()> {
        self.delta.insert(key, Some(val));
        Ok(())
    }

    fn del(&mut self, key: &[u8]) -> crate::Result<()> {
        self.delta.insert(key.to_vec(), None);
        Ok(())
    }
}

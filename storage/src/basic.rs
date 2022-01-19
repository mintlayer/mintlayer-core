use crate::schema::{self, Schema};
use std::collections::BTreeMap;
use common::sync;

type Data = Vec<u8>;

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
    maps: sync::Arc<sync::Mutex<StoreMapSet>>,
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
            maps: sync::Arc::new(sync::Mutex::new(Sch::init())),
            _phantom: Default::default(),
        }
    }
}

impl<'st, Sch: Schema> crate::transaction::Transactional<'st> for Store<Sch> {
    type Transaction = Transaction<'st, Sch>;

    fn start_transaction(&'st mut self) -> Self::Transaction {
        Transaction::start(self)
    }
}

impl<Sch: InitStore> Default for Store<Sch> {
    fn default() -> Self {
        Self::new()
    }
}

/// Store transaction.
///
/// Contains a pointer to the original store and a set of changes to it. If the transaction is
/// commited, the changes are flushed to the store. If the transaction is aborted, the changes are
/// discarded.
pub struct Transaction<'st, Sch: Schema> {
    store: sync::MutexGuard<'st, StoreMapSet>,
    delta: DeltaMapSet,
    _phantom: std::marker::PhantomData<Sch>,
}

impl<'st, Sch: Schema> Transaction<'st, Sch> {
    // Start a transaction on given store
    fn start(store: &'st Store<Sch>) -> Self {
        let store = store.maps.lock().expect("Mutex locked by a crashed thread");
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

    /// Get key-value store for given column (key-to-single-value only for now)
    pub fn get<Col, I>(&mut self) -> SingleMap<'_>
    where
        Col: schema::Column<Kind = schema::Single>,
        Sch: schema::HasColumn<Col, I>,
    {
        match (self.store.get(Col::NAME), self.delta.get_mut(Col::NAME)) {
            (Some(StoreMap::Single(store)), Some(DeltaMap::Single(delta))) => {
                SingleMap::new(store, delta)
            }
            _ => panic!("Unexpected map kind"),
        }
    }
}

impl<'st, Sch: Schema> crate::transaction::DbTransaction for Transaction<'st, Sch> {
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

/// Represents a key-value store with keys mapping to one value.
pub struct SingleMap<'tx> {
    store: &'tx StoreMapSingle,
    delta: &'tx mut DeltaMapSingle,
}

impl<'tx> SingleMap<'tx> {
    fn new(store: &'tx StoreMapSingle, delta: &'tx mut DeltaMapSingle) -> Self {
        Self { store, delta }
    }

    /// Get value associated with given key
    pub fn get(&self, key: impl AsRef<[u8]>) -> crate::Result<Option<&[u8]>> {
        let res = match &self.delta.get(key.as_ref()) {
            Some(val) => val.as_ref(),
            None => self.store.get(key.as_ref()),
        };
        Ok(res.map(AsRef::as_ref))
    }

    /// Insert a value associated with given key, overwriting the original one.
    pub fn put(&mut self, key: Data, val: Data) -> crate::Result<()> {
        self.delta.insert(key, Some(val));
        Ok(())
    }

    /// Delete the value associated with given key.
    pub fn del(&mut self, key: impl AsRef<[u8]>) -> crate::Result<()> {
        self.delta.insert(key.as_ref().to_vec(), None);
        Ok(())
    }
}

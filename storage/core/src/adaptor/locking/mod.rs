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

//! A simple adaptor to add transaction capability to a type that only implements the basic
//! read/write operations, giving a full-featured (albeit not necessarily efficient) backend.

mod prefix_iter_rw;

use crate::{
    adaptor::{Construct, CoreOps},
    backend,
    info::{DbDesc, DbIndex},
    Data,
};
use backend::{PrefixIter, ReadOps, WriteOps};

use std::{borrow::Cow, collections::BTreeMap};
use utils::sync;

// Read-only transaction just holds a read lock to the database
pub struct TxRo<'tx, T>(sync::RwLockReadGuard<'tx, T>);

impl<'tx, T: ReadOps> ReadOps for TxRo<'tx, T> {
    fn get(&self, idx: DbIndex, key: &[u8]) -> crate::Result<Option<Cow<[u8]>>> {
        self.0.get(idx, key)
    }
}

impl<'tx, 'i, T: PrefixIter<'i>> PrefixIter<'i> for TxRo<'tx, T> {
    type Iterator = T::Iterator;

    fn prefix_iter<'m: 'i>(&'m self, idx: DbIndex, prefix: Data) -> crate::Result<Self::Iterator> {
        self.0.prefix_iter(idx, prefix)
    }
}

impl<'tx, T: ReadOps> backend::TxRo for TxRo<'tx, T> {}

// Tracker for database changes
type DeltaMap = BTreeMap<Data, Option<Data>>;

// RW transaction holds a write lock to the database and a list of changes performed
pub struct TxRw<'tx, T> {
    db: sync::RwLockWriteGuard<'tx, T>,
    deltas: Vec<DeltaMap>,
}

impl<'tx, T> TxRw<'tx, T> {
    fn update(&mut self, idx: DbIndex, key: Data, val: Option<Data>) -> crate::Result<()> {
        self.deltas[idx.get()].insert(key, val);
        Ok(())
    }
}

impl<'tx, T: ReadOps> ReadOps for TxRw<'tx, T> {
    fn get(&self, idx: DbIndex, key: &[u8]) -> crate::Result<Option<Cow<[u8]>>> {
        self.deltas[idx.get()].get(key).map_or_else(
            || self.db.get(idx, key),
            |x| Ok(x.as_deref().map(|p| p.into())),
        )
    }
}

impl<'tx, 'i, T: PrefixIter<'i>> PrefixIter<'i> for TxRw<'tx, T> {
    type Iterator = prefix_iter_rw::Iter<'i, T>;

    fn prefix_iter<'m: 'i>(&'m self, idx: DbIndex, prefix: Data) -> crate::Result<Self::Iterator> {
        prefix_iter_rw::iter(self, idx, prefix)
    }
}

impl<'tx, T> WriteOps for TxRw<'tx, T> {
    fn put(&mut self, idx: DbIndex, key: Data, val: Data) -> crate::Result<()> {
        self.update(idx, key, Some(val))
    }

    fn del(&mut self, idx: DbIndex, key: &[u8]) -> crate::Result<()> {
        self.update(idx, key.to_vec(), None)
    }
}

impl<'tx, T: ReadOps + WriteOps> backend::TxRw for TxRw<'tx, T> {
    fn commit(mut self) -> crate::Result<()> {
        let entries = self.deltas.into_iter().enumerate().map(|(i, m)| (DbIndex::new(i), m));
        for (idx, kvmap) in entries {
            for (key, val) in kvmap {
                match val {
                    None => self.db.del(idx, &key)?,
                    Some(val) => self.db.put(idx, key, val)?,
                }
            }
        }
        Ok(())
    }
}

pub struct TransactionLockImpl<T> {
    db: sync::Arc<sync::RwLock<T>>,
    num_maps: usize,
}

impl<T> Clone for TransactionLockImpl<T> {
    fn clone(&self) -> Self {
        Self {
            db: sync::Arc::clone(&self.db),
            num_maps: self.num_maps,
        }
    }
}

impl<T> utils::shallow_clone::ShallowClone for TransactionLockImpl<T> {}

impl<'tx, T: 'tx + ReadOps> backend::TransactionalRo<'tx> for TransactionLockImpl<T> {
    type TxRo = TxRo<'tx, T>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TxRo> {
        Ok(TxRo(self.db.read().expect("lock to be alive")))
    }
}

impl<'tx, T: 'tx + ReadOps + WriteOps> backend::TransactionalRw<'tx> for TransactionLockImpl<T> {
    type TxRw = TxRw<'tx, T>;

    fn transaction_rw<'st: 'tx>(&'st self) -> crate::Result<Self::TxRw> {
        Ok(TxRw {
            db: self.db.write().expect("lock to be alive"),
            deltas: vec![BTreeMap::new(); self.num_maps],
        })
    }
}

impl<T: CoreOps + Sync + Send + 'static> backend::BackendImpl for TransactionLockImpl<T> {}

/// Add lock-based transactions to given bare backend implementation.
///
/// Given a type `T` implementing core database operations [CoreOps], this creates a full-featured
/// backend by adding the transaction capability. It uses a combination of locking and change
/// tracking to implement the transaction functionality.
pub struct Locking<T: Construct>(T::From);

impl<T: Construct> Clone for Locking<T>
where
    T::From: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: CoreOps + Sync + Send + 'static> backend::Backend for Locking<T>
where
    T::From: Clone,
{
    type Impl = TransactionLockImpl<T>;

    fn open(self, desc: DbDesc) -> crate::Result<Self::Impl> {
        let num_maps = desc.len();
        let db = sync::Arc::new(sync::RwLock::new(T::construct(self.0, desc)?));
        Ok(TransactionLockImpl { db, num_maps })
    }
}

impl<T: Construct> Locking<T> {
    pub fn new(inner: T::From) -> Self {
        Self(inner)
    }
}

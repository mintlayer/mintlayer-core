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

use crate::{
    adaptor::{Construct, CoreOps},
    backend::{self, ReadOps, WriteOps},
    util::MapPrefixIter,
    Data, DbDesc, DbMapCount, DbMapId, DbMapsData,
};

use itertools::EitherOrBoth;
use std::{borrow::Cow, collections::BTreeMap};
use utils::{const_value::ConstValue, sync};

// Read-only transaction just holds a read lock to the database
pub struct TxRo<'tx, T>(sync::RwLockReadGuard<'tx, T>);

impl<T: ReadOps> ReadOps for TxRo<'_, T> {
    fn get(&self, map_id: DbMapId, key: &[u8]) -> crate::Result<Option<Cow<'_, [u8]>>> {
        self.0.get(map_id, key)
    }

    fn prefix_iter(
        &self,
        map_id: DbMapId,
        prefix: Data,
    ) -> crate::Result<impl Iterator<Item = (Data, Data)> + '_> {
        self.0.prefix_iter(map_id, prefix)
    }

    fn greater_equal_iter(
        &self,
        map_id: DbMapId,
        key: Data,
    ) -> crate::Result<impl Iterator<Item = (Data, Data)> + '_> {
        self.0.greater_equal_iter(map_id, key)
    }
}

impl<T: ReadOps> backend::TxRo for TxRo<'_, T> {}

// Tracker for database changes
type DeltaMap = BTreeMap<Data, Option<Data>>;

// RW transaction holds a write lock to the database and a list of changes performed
pub struct TxRw<'tx, T> {
    db: sync::RwLockWriteGuard<'tx, T>,
    deltas: DbMapsData<DeltaMap>,
}

impl<T> TxRw<'_, T> {
    fn update(&mut self, map_id: DbMapId, key: Data, val: Option<Data>) -> crate::Result<()> {
        self.deltas[map_id].insert(key, val);
        Ok(())
    }
}

impl<T: ReadOps> ReadOps for TxRw<'_, T> {
    fn get(&self, map_id: DbMapId, key: &[u8]) -> crate::Result<Option<Cow<'_, [u8]>>> {
        self.deltas[map_id].get(key).map_or_else(
            || self.db.get(map_id, key),
            |x| Ok(x.as_deref().map(|p| p.into())),
        )
    }

    fn prefix_iter(
        &self,
        map_id: DbMapId,
        prefix: Data,
    ) -> crate::Result<impl Iterator<Item = (Data, Data)> + '_> {
        let db_iter = self.db.prefix_iter(map_id, prefix.clone())?;
        let delta_iter = MapPrefixIter::new(&self.deltas[map_id], prefix.clone());

        Ok(merge_iterators(db_iter, delta_iter))
    }

    fn greater_equal_iter(
        &self,
        map_id: DbMapId,
        key: Data,
    ) -> crate::Result<impl Iterator<Item = (Data, Data)> + '_> {
        let db_iter = self.db.greater_equal_iter(map_id, key.clone())?;
        let delta_iter = self.deltas[map_id].range(key..);

        Ok(merge_iterators(db_iter, delta_iter))
    }
}

fn merge_iterators<'a>(
    db_iter: impl Iterator<Item = (Data, Data)> + 'a,
    delta_iter: impl Iterator<Item = (&'a Data, &'a Option<Data>)> + 'a,
) -> impl Iterator<Item = (Data, Data)> + 'a {
    itertools::merge_join_by(db_iter, delta_iter, |(k1, _), (k2, _)| k1.cmp(k2)).filter_map(
        |item| {
            match item {
                // Item only in original db, just present it
                EitherOrBoth::Left(l) => Some(l),
                // If the entry is present in both database and the delta map, the delta map takes
                // precedence. If it only is in the delta map, just take that.
                EitherOrBoth::Right((k, v)) | EitherOrBoth::Both(_, (k, v)) => {
                    v.as_ref().map(|v| (k.clone(), v.clone()))
                }
            }
        },
    )
}

impl<T> WriteOps for TxRw<'_, T> {
    fn put(&mut self, map_id: DbMapId, key: Data, val: Data) -> crate::Result<()> {
        self.update(map_id, key, Some(val))
    }

    fn del(&mut self, map_id: DbMapId, key: &[u8]) -> crate::Result<()> {
        self.update(map_id, key.to_vec(), None)
    }
}

impl<T: ReadOps + WriteOps> backend::TxRw for TxRw<'_, T> {
    fn commit(mut self) -> crate::Result<()> {
        for (idx, kvmap) in self.deltas.into_iter_with_id() {
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
    num_maps: ConstValue<DbMapCount>,
}

impl<T> Clone for TransactionLockImpl<T> {
    fn clone(&self) -> Self {
        Self {
            db: sync::Arc::clone(&self.db),
            num_maps: self.num_maps,
        }
    }
}

impl<T> utils::shallow_clone::ShallowClone for TransactionLockImpl<T> {
    fn shallow_clone(&self) -> Self {
        Self {
            db: self.db.shallow_clone(),
            num_maps: self.num_maps.shallow_clone(),
        }
    }
}

impl<T: CoreOps + Sync + Send + 'static> backend::BackendImpl for TransactionLockImpl<T> {
    type TxRo<'a> = TxRo<'a, T>;

    type TxRw<'a> = TxRw<'a, T>;

    fn transaction_ro(&self) -> crate::Result<Self::TxRo<'_>> {
        Ok(TxRo(self.db.read().expect("lock to be alive")))
    }

    fn transaction_rw(&self, _size: Option<usize>) -> crate::Result<Self::TxRw<'_>> {
        Ok(TxRw {
            db: self.db.write().expect("lock to be alive"),
            deltas: DbMapsData::new(*self.num_maps, |_| BTreeMap::new()),
        })
    }
}

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
        let num_maps = desc.db_map_count().into();
        let db = sync::Arc::new(sync::RwLock::new(T::construct(self.0, desc)?));
        Ok(TransactionLockImpl { db, num_maps })
    }
}

impl<T: Construct> Locking<T> {
    pub fn new(inner: T::From) -> Self {
        Self(inner)
    }
}

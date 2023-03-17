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

//! High-level application-agnostic storage interface

mod internal;
pub mod raw;

use std::borrow::Cow;

use internal::{EntryIterator, TxImpl};
use utils::shallow_clone::ShallowClone;

use crate::schema::{self, Schema};
use serialization::{encoded::Encoded, Encode, EncodeLike};
use storage_core::{backend, Backend, DbMapId};

/// The main storage type
pub struct Storage<B: Backend, Sch> {
    backend: B::Impl,
    _schema: core::marker::PhantomData<Sch>,
}

impl<B: Backend, Sch> Clone for Storage<B, Sch>
where
    B::Impl: ShallowClone,
{
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            _schema: Default::default(),
        }
    }
}

impl<B: Backend, Sch> ShallowClone for Storage<B, Sch>
where
    B::Impl: ShallowClone,
{
    fn shallow_clone(&self) -> Self {
        Self {
            backend: self.backend.shallow_clone(),
            _schema: self._schema.shallow_clone(),
        }
    }
}

impl<B: Backend, Sch: Schema> Storage<B, Sch> {
    /// Create new storage with given backend
    pub fn new(backend: B) -> crate::Result<Self> {
        let backend = backend.open(storage_core::types::construct::db_desc(Sch::desc_iter()))?;
        let _schema = std::marker::PhantomData;
        Ok(Self { backend, _schema })
    }

    /// Dump raw database contents into a data structure
    pub fn dump_raw(&self) -> crate::Result<raw::StorageContents<Sch>> {
        raw::dump_storage(self)
    }

    /// Start a read-only transaction
    pub fn transaction_ro(&self) -> crate::Result<TransactionRo<'_, B, Sch>> {
        let dbtx = backend::BackendImpl::transaction_ro(&self.backend)?;
        let _schema = std::marker::PhantomData;
        Ok(TransactionRo { dbtx, _schema })
    }

    /// Start a read-write transaction
    pub fn transaction_rw(&self, size: Option<usize>) -> crate::Result<TransactionRw<'_, B, Sch>> {
        let dbtx = backend::BackendImpl::transaction_rw(&self.backend, size)?;
        let _schema = std::marker::PhantomData;
        Ok(TransactionRw { dbtx, _schema })
    }
}

/// A read-only transaction
pub struct TransactionRo<'tx, B: Backend, Sch> {
    dbtx: <Self as TxImpl>::Impl,
    _schema: core::marker::PhantomData<Sch>,
}

impl<'tx, B: Backend, Sch: Schema> TransactionRo<'tx, B, Sch> {
    /// Get key-value map immutably (key-to-single-value only for now)
    pub fn get<DbMap: schema::DbMap, I>(&self) -> MapRef<Self, DbMap>
    where
        Sch: schema::HasDbMap<DbMap, I>,
    {
        MapRef::new(&self.dbtx, <Sch as schema::HasDbMap<DbMap, I>>::INDEX)
    }

    /// Close the read-only transaction early
    pub fn close(self) {
        // Let backend tx destructor do the heavy lifting
    }
}

/// A read-write transaction
pub struct TransactionRw<'tx, B: Backend, Sch> {
    dbtx: <Self as TxImpl>::Impl,
    _schema: core::marker::PhantomData<Sch>,
}

impl<'tx, B: Backend, Sch: Schema> TransactionRw<'tx, B, Sch> {
    /// Get key-value map immutably (key-to-single-value only for now)
    pub fn get<DbMap: schema::DbMap, I>(&self) -> MapRef<Self, DbMap>
    where
        Sch: schema::HasDbMap<DbMap, I>,
    {
        MapRef::new(&self.dbtx, <Sch as schema::HasDbMap<DbMap, I>>::INDEX)
    }

    /// Get key-value map immutably (key-to-single-value only for now)
    pub fn get_mut<DbMap: schema::DbMap, I>(&mut self) -> MapMut<Self, DbMap>
    where
        Sch: schema::HasDbMap<DbMap, I>,
    {
        MapMut::new(&mut self.dbtx, <Sch as schema::HasDbMap<DbMap, I>>::INDEX)
    }

    /// Commit the transaction
    pub fn commit(self) -> crate::Result<()> {
        backend::TxRw::commit(self.dbtx)
    }

    /// Abort the transaction
    pub fn abort(self) {
        // Let backend tx destructor do the heavy lifting
    }
}

/// Represents an immutable view of a key-value map
pub struct MapRef<'tx, Tx: TxImpl, DbMap: schema::DbMap> {
    dbtx: &'tx Tx::Impl,
    map_id: DbMapId,
    _phantom: std::marker::PhantomData<fn() -> DbMap>,
}

impl<'tx, Tx: TxImpl, DbMap: schema::DbMap> MapRef<'tx, Tx, DbMap> {
    fn new(dbtx: &'tx Tx::Impl, map_id: DbMapId) -> Self {
        let _phantom = Default::default();
        Self {
            dbtx,
            map_id,
            _phantom,
        }
    }
}

impl<Tx: TxImpl, DbMap: schema::DbMap> MapRef<'_, Tx, DbMap>
where
    Tx::Impl: backend::ReadOps,
{
    /// Get value associated with given key
    #[allow(clippy::type_complexity)]
    pub fn get<K: EncodeLike<DbMap::Key>>(
        &self,
        key: K,
    ) -> crate::Result<Option<Encoded<Cow<[u8]>, DbMap::Value>>> {
        internal::get::<DbMap, _, _>(self.dbtx, self.map_id, key)
    }

    /// Iterator over entries with key starting with given prefix
    pub fn prefix_iter<Pfx>(&self, prefix: &Pfx) -> crate::Result<impl '_ + EntryIterator<DbMap>>
    where
        Pfx: Encode,
        DbMap::Key: HasPrefix<Pfx>,
    {
        internal::prefix_iter(self.dbtx, self.map_id, prefix.encode())
    }

    /// Iterator over decoded entries with key starting with given prefix
    pub fn prefix_iter_decoded<Pfx>(
        &self,
        prefix: &Pfx,
    ) -> crate::Result<impl '_ + Iterator<Item = (DbMap::Key, DbMap::Value)>>
    where
        Pfx: Encode,
        DbMap::Key: HasPrefix<Pfx>,
    {
        self.prefix_iter(prefix).map(|item| item.map(|(k, v)| (k, v.decode())))
    }
}

/// Represents a mutable view of a key-value map
pub struct MapMut<'tx, Tx: TxImpl, DbMap: schema::DbMap> {
    dbtx: &'tx mut Tx::Impl,
    map_id: DbMapId,
    _phantom: std::marker::PhantomData<fn() -> DbMap>,
}

impl<'tx, Tx: TxImpl, DbMap: schema::DbMap> MapMut<'tx, Tx, DbMap> {
    fn new(dbtx: &'tx mut Tx::Impl, map_id: DbMapId) -> Self {
        let _phantom = Default::default();
        Self {
            dbtx,
            map_id,
            _phantom,
        }
    }
}

impl<Tx: TxImpl, DbMap: schema::DbMap> MapMut<'_, Tx, DbMap>
where
    Tx::Impl: backend::ReadOps,
{
    /// Get value associated with given key
    #[allow(clippy::type_complexity)]
    pub fn get<K: EncodeLike<DbMap::Key>>(
        &self,
        key: K,
    ) -> crate::Result<Option<Encoded<Cow<[u8]>, DbMap::Value>>> {
        internal::get::<DbMap, _, _>(self.dbtx, self.map_id, key)
    }

    /// Iterator over entries with key starting with given prefix
    pub fn prefix_iter<Pfx>(&self, prefix: &Pfx) -> crate::Result<impl '_ + EntryIterator<DbMap>>
    where
        Pfx: Encode,
        DbMap::Key: HasPrefix<Pfx>,
    {
        internal::prefix_iter(self.dbtx, self.map_id, prefix.encode())
    }
}

impl<Tx: TxImpl, DbMap: schema::DbMap> MapMut<'_, Tx, DbMap>
where
    Tx::Impl: backend::ReadOps + backend::WriteOps,
{
    /// Put a new value associated with given key. Overwrites the previous one.
    pub fn put<K: EncodeLike<DbMap::Key>, V: EncodeLike<DbMap::Value>>(
        &mut self,
        key: K,
        value: V,
    ) -> crate::Result<()> {
        backend::WriteOps::put(self.dbtx, self.map_id, key.encode(), value.encode())
    }

    /// Remove value associated with given key.
    pub fn del<K: EncodeLike<DbMap::Key>>(&mut self, key: K) -> crate::Result<()> {
        key.using_encoded(|key| backend::WriteOps::del(self.dbtx, self.map_id, key))
    }
}

/// Marker asserting type `Pfx` is an encoding prefix of `Self`
pub trait HasPrefix<Pfx: Encode>: Encode {}

// The unit type is a prefix of everything
impl<T: Encode> HasPrefix<()> for T {}
// Tuples can be broken down into parts. Up to 3-tuples for now, can be extended as needed
impl<T: Encode, U: Encode> HasPrefix<(T,)> for (T, U) {}
impl<T: Encode, U: Encode, W: Encode> HasPrefix<(T,)> for (T, U, W) {}
impl<T: Encode, U: Encode, W: Encode> HasPrefix<(T, U)> for (T, U, W) {}

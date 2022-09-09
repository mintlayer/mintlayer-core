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

use internal::{EntryIterator, TxImpl};

use crate::schema::{self, Schema};
use serialization::{encoded::Encoded, Encode, EncodeLike};
use storage_core::{backend, Backend, DbIndex};

/// The main storage type
pub struct Storage<B: Backend, Sch> {
    backend: B::Impl,
    _schema: core::marker::PhantomData<Sch>,
}

impl<B: Backend, Sch> Clone for Storage<B, Sch>
where
    B::Impl: Clone,
{
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            _schema: Default::default(),
        }
    }
}

impl<B: Backend, Sch: Schema> Storage<B, Sch> {
    /// Create new storage with given backend
    pub fn new(backend: B) -> crate::Result<Self> {
        Ok(Self {
            backend: backend.open(Sch::desc_iter().collect())?,
            _schema: Default::default(),
        })
    }

    /// Start a read-only transaction
    pub fn transaction_ro<'tx, 'st: 'tx>(&'st self) -> TransactionRo<'tx, B, Sch> {
        TransactionRo {
            dbtx: backend::TransactionalRo::transaction_ro(&self.backend),
            _schema: Default::default(),
        }
    }

    /// Start a read-write transaction
    pub fn transaction_rw<'tx, 'st: 'tx>(&'st self) -> TransactionRw<'tx, B, Sch> {
        TransactionRw {
            dbtx: backend::TransactionalRw::transaction_rw(&self.backend),
            _schema: Default::default(),
        }
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
pub struct MapRef<'tx, Tx: internal::TxImpl, DbMap: schema::DbMap> {
    dbtx: &'tx Tx::Impl,
    idx: DbIndex,
    _phantom: std::marker::PhantomData<fn() -> DbMap>,
}

impl<'tx, Tx: TxImpl, DbMap: schema::DbMap> MapRef<'tx, Tx, DbMap> {
    fn new(dbtx: &'tx Tx::Impl, idx: DbIndex) -> Self {
        let _phantom = Default::default();
        Self {
            dbtx,
            idx,
            _phantom,
        }
    }
}

impl<Tx: TxImpl, DbMap: schema::DbMap> MapRef<'_, Tx, DbMap>
where
    Tx::Impl: backend::ReadOps,
{
    /// Get value associated with given key
    pub fn get<K: EncodeLike<DbMap::Key>>(
        &self,
        key: K,
    ) -> crate::Result<Option<Encoded<&[u8], DbMap::Value>>> {
        internal::get::<DbMap, _, _>(self.dbtx, self.idx, key)
    }

    /// Iterator over entries with key starting with given prefix
    pub fn prefix_iter<Pfx>(&self, prefix: &Pfx) -> crate::Result<impl '_ + EntryIterator<DbMap>>
    where
        Pfx: Encode,
        DbMap::Key: HasPrefix<Pfx>,
    {
        internal::prefix_iter(self.dbtx, self.idx, prefix.encode())
    }
}

/// Represents a mutable view of a key-value map
pub struct MapMut<'tx, Tx: TxImpl, DbMap: schema::DbMap> {
    dbtx: &'tx mut Tx::Impl,
    idx: DbIndex,
    _phantom: std::marker::PhantomData<fn() -> DbMap>,
}

impl<'tx, Tx: TxImpl, DbMap: schema::DbMap> MapMut<'tx, Tx, DbMap> {
    fn new(dbtx: &'tx mut Tx::Impl, idx: DbIndex) -> Self {
        let _phantom = Default::default();
        Self {
            dbtx,
            idx,
            _phantom,
        }
    }
}

impl<Tx: TxImpl, DbMap: schema::DbMap> MapMut<'_, Tx, DbMap>
where
    Tx::Impl: backend::ReadOps,
{
    /// Get value associated with given key
    pub fn get<K: EncodeLike<DbMap::Key>>(
        &self,
        key: K,
    ) -> crate::Result<Option<Encoded<&[u8], DbMap::Value>>> {
        internal::get::<DbMap, _, _>(self.dbtx, self.idx, key)
    }

    /// Iterator over entries with key starting with given prefix
    pub fn prefix_iter<Pfx>(&self, prefix: &Pfx) -> crate::Result<impl '_ + EntryIterator<DbMap>>
    where
        Pfx: Encode,
        DbMap::Key: HasPrefix<Pfx>,
    {
        internal::prefix_iter(self.dbtx, self.idx, prefix.encode())
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
        backend::WriteOps::put(self.dbtx, self.idx, key.encode(), value.encode())
    }

    /// Remove value associated with given key.
    pub fn del<K: EncodeLike<DbMap::Key>>(&mut self, key: K) -> crate::Result<()> {
        key.using_encoded(|key| backend::WriteOps::del(self.dbtx, self.idx, key))
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

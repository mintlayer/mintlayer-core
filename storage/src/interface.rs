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

use crate::schema::{self, Schema};
use storage_core::{backend, Backend, Data, DbIndex};

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

/// Map high-level transaction type to the backend-specific implementation type
pub trait TxImpl {
    /// The implementation type
    type Impl;
}

/// A read-only transaction
pub struct TransactionRo<'tx, B: Backend, Sch> {
    dbtx: <Self as TxImpl>::Impl,
    _schema: core::marker::PhantomData<Sch>,
}

impl<'tx, B: Backend, Sch> TxImpl for TransactionRo<'tx, B, Sch> {
    type Impl = <B::Impl as backend::TransactionalRo<'tx>>::TxRo;
}

impl<'tx, B: Backend, Sch: Schema> TransactionRo<'tx, B, Sch> {
    /// Get key-value map immutably (key-to-single-value only for now)
    pub fn get<DbMap, I>(&self) -> MapRef<'_, Self>
    where
        DbMap: schema::DbMap<Kind = schema::Single>,
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

impl<'tx, B: Backend, Sch> TxImpl for TransactionRw<'tx, B, Sch> {
    type Impl = <B::Impl as backend::TransactionalRw<'tx>>::TxRw;
}

impl<'tx, B: Backend, Sch: Schema> TransactionRw<'tx, B, Sch> {
    /// Get key-value map immutably (key-to-single-value only for now)
    pub fn get<DbMap, I>(&self) -> MapRef<Self>
    where
        DbMap: schema::DbMap<Kind = schema::Single>,
        Sch: schema::HasDbMap<DbMap, I>,
    {
        MapRef::new(&self.dbtx, <Sch as schema::HasDbMap<DbMap, I>>::INDEX)
    }

    /// Get key-value map immutably (key-to-single-value only for now)
    pub fn get_mut<DbMap, I>(&mut self) -> MapMut<Self>
    where
        DbMap: schema::DbMap<Kind = schema::Single>,
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
pub struct MapRef<'tx, Tx: TxImpl> {
    dbtx: &'tx Tx::Impl,
    idx: DbIndex,
}

impl<'tx, Tx: TxImpl> MapRef<'tx, Tx> {
    fn new(dbtx: &'tx Tx::Impl, idx: DbIndex) -> Self {
        Self { dbtx, idx }
    }
}

impl<Tx: TxImpl> MapRef<'_, Tx>
where
    Tx::Impl: backend::ReadOps,
{
    pub fn get(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
        backend::ReadOps::get(self.dbtx, self.idx, key)
    }
}

/// Represents a mutable view of a key-value map
pub struct MapMut<'tx, Tx: TxImpl> {
    dbtx: &'tx mut Tx::Impl,
    idx: DbIndex,
}

impl<'tx, Tx: TxImpl> MapMut<'tx, Tx> {
    fn new(dbtx: &'tx mut Tx::Impl, idx: DbIndex) -> Self {
        Self { dbtx, idx }
    }
}

impl<Tx: TxImpl> MapMut<'_, Tx>
where
    Tx::Impl: backend::ReadOps,
{
    pub fn get(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
        backend::ReadOps::get(self.dbtx, self.idx, key)
    }
}

impl<Tx: TxImpl> MapMut<'_, Tx>
where
    Tx::Impl: backend::ReadOps + backend::WriteOps,
{
    pub fn put(&mut self, key: Data, value: Data) -> crate::Result<()> {
        backend::WriteOps::put(self.dbtx, self.idx, key, value)
    }

    pub fn del(&mut self, key: &[u8]) -> crate::Result<()> {
        backend::WriteOps::del(self.dbtx, self.idx, key)
    }
}

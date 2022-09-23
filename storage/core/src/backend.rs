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

//! Low-level interface implemented by storage backends.

pub use crate::{
    info::{DbDesc, DbIndex},
    Data,
};

/// Types providing capability of iterating over keys with given prefix
pub trait PrefixIter<'i> {
    /// The iterator type
    type Iterator: 'i + Iterator<Item = (Data, Data)>;

    /// Get iterator over key-value pairs where the key has given prefix
    fn prefix_iter<'m: 'i>(&'m self, idx: DbIndex, prefix: Data) -> crate::Result<Self::Iterator>;
}

/// Read-only database operations
pub trait ReadOps: for<'i> PrefixIter<'i> {
    /// Get value associated with given key.
    fn get(&self, idx: DbIndex, key: &[u8]) -> crate::Result<Option<&[u8]>>;
}

/// Write database operation
pub trait WriteOps {
    /// Set value associated with given key.
    fn put(&mut self, idx: DbIndex, key: Data, val: Data) -> crate::Result<()>;

    /// Delete the value associated with given key.
    fn del(&mut self, idx: DbIndex, key: &[u8]) -> crate::Result<()>;
}

/// Read-only transaction
///
/// If a clenup is required when the transaction closes, [Drop] should be implemented too.
pub trait TxRo: ReadOps {}

/// Read-write transaction
///
/// If a clenup is required when the transaction closes, [Drop] should be implemented too.
pub trait TxRw: ReadOps + WriteOps {
    /// Commit changes from this transaction
    fn commit(self) -> crate::Result<()>;
}

/// Read-only transactional interface to the storage
pub trait TransactionalRo<'tx> {
    /// Read-only transaction internal type
    type TxRo: TxRo + 'tx;

    /// Start a read-only transaction
    fn transaction_ro<'st: 'tx>(&'st self) -> Self::TxRo;
}

/// Read-write transactional interface to the storage
pub trait TransactionalRw<'tx> {
    /// Start a read-write transaction
    type TxRw: TxRw + 'tx;

    /// Start a read-write transaction
    fn transaction_rw<'st: 'tx>(&'st self) -> Self::TxRw;
}

/// Storage backend internal implementation type
pub trait BackendImpl:
    'static + for<'tx> TransactionalRo<'tx> + for<'tx> TransactionalRw<'tx> + Send + Sync + Clone
{
}

/// Storage backend type. Used to set up storage.
pub trait Backend {
    /// Implementation type corresponding to this backend
    type Impl: BackendImpl;

    /// Open the database, giving an implementation-specific handle
    fn open(self, desc: DbDesc) -> crate::Result<Self::Impl>;
}

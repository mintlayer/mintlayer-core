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

use std::borrow::Cow;

use utils::shallow_clone::ShallowClone;

pub use crate::{Data, DbDesc, DbMapId};

/// Read-only database operations
pub trait ReadOps {
    /// The prefix iterator type
    type PrefixIter<'i>: Iterator<Item = (Data, Data)> + 'i
    where
        Self: 'i;

    /// Get value associated with given key.
    fn get(&self, map_id: DbMapId, key: &[u8]) -> crate::Result<Option<Cow<[u8]>>>;

    /// Get iterator over key-value pairs where the key has given prefix
    fn prefix_iter(&self, map_id: DbMapId, prefix: Data) -> crate::Result<Self::PrefixIter<'_>>;
}

/// Write database operation
pub trait WriteOps {
    /// Set value associated with given key.
    fn put(&mut self, map_id: DbMapId, key: Data, val: Data) -> crate::Result<()>;

    /// Delete the value associated with given key.
    fn del(&mut self, map_id: DbMapId, key: &[u8]) -> crate::Result<()>;
}

/// Read-only transaction
///
/// If a cleanup is required when the transaction closes, [Drop] should be implemented too.
pub trait TxRo: ReadOps {}

/// Read-write transaction
///
/// If a cleanup is required when the transaction closes, [Drop] should be implemented too.
pub trait TxRw: ReadOps + WriteOps {
    /// Commit changes from this transaction
    fn commit(self) -> crate::Result<()>;
}

/// Storage backend internal implementation type
pub trait BackendImpl: 'static + Send + Sync + ShallowClone {
    /// Read-only transaction internal type
    type TxRo<'a>: TxRo + 'a;

    /// Start a read-write transaction
    type TxRw<'a>: TxRw + 'a;

    /// Start a read-only transaction
    fn transaction_ro(&self) -> crate::Result<Self::TxRo<'_>>;

    /// Start a read-write transaction
    fn transaction_rw(&self, size: Option<usize>) -> crate::Result<Self::TxRw<'_>>;
}

/// Storage backend type. Used to set up storage.
pub trait Backend {
    /// Implementation type corresponding to this backend
    type Impl: BackendImpl;

    /// Open the database, giving an implementation-specific handle
    fn open(self, desc: DbDesc) -> crate::Result<Self::Impl>;
}

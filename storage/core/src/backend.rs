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
    /// Get value associated with given key.
    fn get(&self, map_id: DbMapId, key: &[u8]) -> crate::Result<Option<Cow<'_, [u8]>>>;

    /// Get iterator over key-value pairs where the key has given prefix
    fn prefix_iter(
        &self,
        map_id: DbMapId,
        prefix: Data,
    ) -> crate::Result<impl Iterator<Item = (Data, Data)> + '_>;

    /// Get iterator over key-value pairs where the key is lexicographically greater or equal to
    /// the specified value.
    fn greater_equal_iter(
        &self,
        map_id: DbMapId,
        key: Data,
    ) -> crate::Result<impl Iterator<Item = (Data, Data)> + '_>;
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

/// The "normal" storage backend type.
///
/// Note that the corresponding `BackendImpl` is non-clonable and that creating an rw transaction
/// borrows it as mutable.
pub trait Backend {
    /// Implementation type corresponding to this backend
    type Impl: BackendImpl;

    /// Open the database, giving an implementation-specific handle
    fn open(self, desc: DbDesc) -> crate::Result<Self::Impl>;
}

/// The implementation type for the "normal" storage backend.
// TODO: ideally, we should get rid of the 'static bound here. This may be useful e.g. in wallet
// tests, where it'd be nice to have a 'decorator' for a reference to an existing storage
// (e.g. to test wallet reloading and to ensure that only ro methods are used).
pub trait BackendImpl: Send + Sync + 'static {
    /// Read-only transaction internal type
    type TxRo<'a>: TxRo + 'a;

    /// Read-write transaction internal type
    type TxRw<'a>: TxRw + 'a;

    /// Start a read-only transaction
    fn transaction_ro(&self) -> crate::Result<Self::TxRo<'_>>;

    /// Start a read-write transaction, borrowing `self` as mutable.
    fn transaction_rw(&mut self, size: Option<usize>) -> crate::Result<Self::TxRw<'_>>;
}

/// The "shared" storage backend type.
///
/// Note that the corresponding `SharedBackend` is shallow-clonable and that an rw transaction
/// can be created from a shared reference.
///
/// Also note that we use this fancy syntax `Backend<Impl = <Self as SharedBackend>::ImplHelper>`
/// in order to force trait bounds propagation, so that requiring `B: SharedBackend` would imply
/// `B: Backend`.
pub trait SharedBackend: Backend<Impl = <Self as SharedBackend>::ImplHelper> {
    type ImplHelper: SharedBackendImpl;
}

/// The implementation type for the "shared" storage backend.
pub trait SharedBackendImpl: BackendImpl + ShallowClone {
    /// Start a read-write transaction from a shared reference to self.
    fn transaction_rw(&self, size: Option<usize>) -> crate::Result<Self::TxRw<'_>>;
}

/// Using `BackendWithSendableTransactions` as a bound will ensure that `TxRo` and `TxRw`
/// are `Send`, to avoid using the verbose bounds on `TxRo`/`TxRw` themselves.
///
/// Note that here we also use the `Backend<Impl = Self::ImplHelper>` syntax in order to
/// force trait bound propagation. Due to this, we can't have an umbrella implementation
/// for this trait for any type T that implements `Backend`, because setting `ImplHelper` to
/// `T::Impl` will lead to infinite recursion during compilation.
pub trait BackendWithSendableTransactions:
    Backend<Impl = <Self as BackendWithSendableTransactions>::ImplHelper>
where
    for<'a> <Self::ImplHelper as BackendImpl>::TxRo<'a>: Send,
    for<'a> <Self::ImplHelper as BackendImpl>::TxRw<'a>: Send,
{
    type ImplHelper: BackendImpl;
}

// Note: since these tests are compile time only, there is no need to hide the module
// under `cfg(test)`.
mod tests {
    use super::*;

    // Check that if `BackendWithSendableTransactions` is used as a trait bound, then
    // the transactions are Send.
    #[allow(unused)]
    #[allow(clippy::unwrap_used)]
    fn test_sendable_tx_trait_bound<T: BackendWithSendableTransactions>(t: <T as Backend>::Impl) {
        let tx = t.transaction_ro().unwrap();
        test_send(tx);

        let mut t = t;
        let tx = t.transaction_rw(None).unwrap();
        test_send(tx);
    }

    fn test_send<T: Send>(_: T) {}
}

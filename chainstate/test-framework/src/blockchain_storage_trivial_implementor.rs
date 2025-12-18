// Copyright (c) 2021-2026 RBB S.r.l
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

use std::sync::Arc;

use chainstate_storage::{BlockchainStorageBackend, BlockchainStorageBackendImpl};
use storage::{Backend, BackendImpl, DbDesc, SharedBackend, SharedBackendImpl};
use utils::{atomics::RelaxedAtomicBool, shallow_clone::ShallowClone};

/// A struct that implements BlockchainStorageBackendImpl by simply storing the `in_reckless_mode`
/// flag in a field.
#[derive(Clone)]
pub struct BlockchainStorageImplTrivialImplementor<T> {
    internal: T,
    in_reckless_mode: Arc<RelaxedAtomicBool>,
}

impl<T: BackendImpl> BackendImpl for BlockchainStorageImplTrivialImplementor<T> {
    type TxRo<'a> = <T as BackendImpl>::TxRo<'a>;
    type TxRw<'a> = <T as BackendImpl>::TxRw<'a>;

    fn transaction_ro(&self) -> storage::Result<Self::TxRo<'_>> {
        self.internal.transaction_ro()
    }

    fn transaction_rw(&mut self, size: Option<usize>) -> storage::Result<Self::TxRw<'_>> {
        self.internal.transaction_rw(size)
    }
}

impl<T: SharedBackendImpl> SharedBackendImpl for BlockchainStorageImplTrivialImplementor<T> {
    fn transaction_rw(&self, size: Option<usize>) -> storage::Result<Self::TxRw<'_>> {
        self.internal.transaction_rw(size)
    }
}

impl<T: ShallowClone> ShallowClone for BlockchainStorageImplTrivialImplementor<T> {
    fn shallow_clone(&self) -> Self {
        Self {
            internal: self.internal.shallow_clone(),
            in_reckless_mode: Arc::clone(&self.in_reckless_mode),
        }
    }
}

impl<T: SharedBackendImpl> BlockchainStorageBackendImpl
    for BlockchainStorageImplTrivialImplementor<T>
{
    fn set_reckless_mode(&self, set: bool) -> chainstate_storage::Result<()> {
        self.in_reckless_mode.store(set);
        Ok(())
    }

    fn in_reckless_mode(&self) -> chainstate_storage::Result<bool> {
        Ok(self.in_reckless_mode.load())
    }
}

/// A struct that implements `BlockchainStorageBackend via `BlockchainStorageImplTrivialImplementor`.
#[derive(Default)]
pub struct BlockchainStorageTrivialImplementor<T>(T);

impl<T> BlockchainStorageTrivialImplementor<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: Backend> Backend for BlockchainStorageTrivialImplementor<T> {
    type Impl = BlockchainStorageImplTrivialImplementor<<T as Backend>::Impl>;

    fn open(self, desc: DbDesc) -> storage::Result<Self::Impl> {
        Ok(BlockchainStorageImplTrivialImplementor {
            internal: self.0.open(desc)?,
            in_reckless_mode: Arc::new(RelaxedAtomicBool::new(false)),
        })
    }
}

impl<T: SharedBackend> SharedBackend for BlockchainStorageTrivialImplementor<T> {
    type ImplHelper = BlockchainStorageImplTrivialImplementor<<T as Backend>::Impl>;
}

impl<T: SharedBackend> BlockchainStorageBackend for BlockchainStorageTrivialImplementor<T> {
    type ImplHelper = BlockchainStorageImplTrivialImplementor<<T as Backend>::Impl>;
}

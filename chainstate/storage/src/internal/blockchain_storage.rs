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

use storage_inmemory::{InMemory, InMemoryImpl};
#[cfg(feature = "lmdb")]
use storage_lmdb::{Lmdb, LmdbImpl};

use crate::Transactional;

pub trait BlockchainStorageBackendImpl: storage::SharedBackendImpl {
    fn set_reckless_mode(&self, set: bool) -> crate::Result<()>;
    fn in_reckless_mode(&self) -> crate::Result<bool>;
}

pub trait BlockchainStorageBackend:
    storage::SharedBackend<ImplHelper = <Self as BlockchainStorageBackend>::ImplHelper>
{
    type ImplHelper: BlockchainStorageBackendImpl;
}

pub trait BlockchainStorage: for<'tx> Transactional<'tx> + Send {
    fn set_reckless_mode(&self, set: bool) -> crate::Result<()>;
    fn in_reckless_mode(&self) -> crate::Result<bool>;
}

// Note: since chainstate-storage is also used (indirectly) by wasm-bindings, we can't have
// an unconditional dependency on LMDB here, because it won't compile for WASM. So we put it
// behind a feature.
#[cfg(feature = "lmdb")]
impl BlockchainStorageBackendImpl for LmdbImpl {
    fn set_reckless_mode(&self, set: bool) -> crate::Result<()> {
        // When switching the reckless mode off, do a sync immediately.
        let force_sync = self.in_reckless_mode()? && !set;

        self.set_no_sync_on_commit(set);

        if force_sync {
            self.force_sync()?;
        }

        Ok(())
    }

    fn in_reckless_mode(&self) -> crate::Result<bool> {
        Ok(self.get_no_sync_on_commit())
    }
}

#[cfg(feature = "lmdb")]
impl BlockchainStorageBackend for Lmdb {
    type ImplHelper = LmdbImpl;
}

impl BlockchainStorageBackendImpl for InMemoryImpl {
    fn set_reckless_mode(&self, _set: bool) -> crate::Result<()> {
        Ok(())
    }

    fn in_reckless_mode(&self) -> crate::Result<bool> {
        Ok(false)
    }
}

impl BlockchainStorageBackend for InMemory {
    type ImplHelper = InMemoryImpl;
}

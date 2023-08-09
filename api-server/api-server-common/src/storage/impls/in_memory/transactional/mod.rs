// Copyright (c) 2023 RBB S.r.l
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

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use common::chain::ChainConfig;

use crate::storage::storage_api::{
    ApiStorage, ApiStorageError, ApiTransactionRo, ApiTransactionRw, Transactional,
};

use super::ApiInMemoryStorage;

pub mod read;
pub mod write;

pub struct ApiInMemoryStorageTransactionalRo<'t> {
    transaction: RwLockReadGuard<'t, ApiInMemoryStorage>,
}

impl<'t> ApiInMemoryStorageTransactionalRo<'t> {
    pub fn new(storage: &'t ThreadSafeApiInMemoryStorage) -> Self {
        Self {
            transaction: storage.tx_ro(),
        }
    }
}

impl<'t> ApiTransactionRo for ApiInMemoryStorageTransactionalRo<'t> {
    fn close(self) -> Result<(), crate::storage::storage_api::ApiStorageError> {
        Ok(())
    }
}

pub struct ApiInMemoryStorageTransactionalRw<'t> {
    transaction: RwLockWriteGuard<'t, ApiInMemoryStorage>,
}

impl<'t> ApiInMemoryStorageTransactionalRw<'t> {
    pub fn new(storage: &'t mut ThreadSafeApiInMemoryStorage) -> Self {
        Self {
            transaction: storage.tx_rw(),
        }
    }
}

impl<'t> ApiTransactionRw for ApiInMemoryStorageTransactionalRw<'t> {
    fn commit(self) -> Result<(), crate::storage::storage_api::ApiStorageError> {
        Ok(())
    }

    fn rollback(self) -> Result<(), crate::storage::storage_api::ApiStorageError> {
        Ok(())
    }
}

pub struct ThreadSafeApiInMemoryStorage {
    storage: RwLock<ApiInMemoryStorage>,
}

impl ThreadSafeApiInMemoryStorage {
    pub fn new(chain_config: &ChainConfig) -> Self {
        Self {
            storage: RwLock::new(ApiInMemoryStorage::new(chain_config)),
        }
    }

    fn tx_ro(&self) -> RwLockReadGuard<'_, ApiInMemoryStorage> {
        self.storage.read().expect("Poisoned mutex")
    }

    fn tx_rw(&mut self) -> RwLockWriteGuard<'_, ApiInMemoryStorage> {
        self.storage.write().expect("Poisoned mutex")
    }
}

impl<'t> Transactional<'t> for ThreadSafeApiInMemoryStorage {
    type TransactionRo = ApiInMemoryStorageTransactionalRo<'t>;

    type TransactionRw = ApiInMemoryStorageTransactionalRw<'t>;

    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, ApiStorageError> {
        Ok(ApiInMemoryStorageTransactionalRo::new(self))
    }

    fn transaction_rw<'s: 't>(&'s mut self) -> Result<Self::TransactionRw, ApiStorageError> {
        Ok(ApiInMemoryStorageTransactionalRw::new(self))
    }
}

impl ApiStorage for ThreadSafeApiInMemoryStorage {}

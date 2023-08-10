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
    ApiServerStorage, ApiServerStorageError, ApiServerTransactionRo, ApiTransactionRw,
    Transactional,
};

use super::ApiServerInMemoryStorage;

pub mod read;
pub mod write;

pub struct ApiServerInMemoryStorageTransactionalRo<'t> {
    transaction: RwLockReadGuard<'t, ApiServerInMemoryStorage>,
}

impl<'t> ApiServerInMemoryStorageTransactionalRo<'t> {
    fn new(storage: &'t TransactionalApiServerInMemoryStorage) -> Self {
        Self {
            transaction: storage.tx_ro(),
        }
    }
}

impl<'t> ApiServerTransactionRo for ApiServerInMemoryStorageTransactionalRo<'t> {
    fn close(self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        Ok(())
    }
}

pub struct ApiServerInMemoryStorageTransactionalRw<'t> {
    transaction: RwLockWriteGuard<'t, ApiServerInMemoryStorage>,
}

impl<'t> ApiServerInMemoryStorageTransactionalRw<'t> {
    fn new(storage: &'t mut TransactionalApiServerInMemoryStorage) -> Self {
        Self {
            transaction: storage.tx_rw(),
        }
    }
}

impl<'t> ApiTransactionRw for ApiServerInMemoryStorageTransactionalRw<'t> {
    fn commit(self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        Ok(())
    }

    fn rollback(self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        Ok(())
    }
}

pub struct TransactionalApiServerInMemoryStorage {
    storage: RwLock<ApiServerInMemoryStorage>,
}

impl TransactionalApiServerInMemoryStorage {
    pub fn new(chain_config: &ChainConfig) -> Self {
        Self {
            storage: RwLock::new(ApiServerInMemoryStorage::new(chain_config)),
        }
    }

    fn tx_ro(&self) -> RwLockReadGuard<'_, ApiServerInMemoryStorage> {
        self.storage.read().expect("Poisoned mutex")
    }

    fn tx_rw(&mut self) -> RwLockWriteGuard<'_, ApiServerInMemoryStorage> {
        self.storage.write().expect("Poisoned mutex")
    }
}

impl<'t> Transactional<'t> for TransactionalApiServerInMemoryStorage {
    type TransactionRo = ApiServerInMemoryStorageTransactionalRo<'t>;

    type TransactionRw = ApiServerInMemoryStorageTransactionalRw<'t>;

    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, ApiServerStorageError> {
        Ok(ApiServerInMemoryStorageTransactionalRo::new(self))
    }

    fn transaction_rw<'s: 't>(&'s mut self) -> Result<Self::TransactionRw, ApiServerStorageError> {
        Ok(ApiServerInMemoryStorageTransactionalRw::new(self))
    }
}

impl ApiServerStorage for TransactionalApiServerInMemoryStorage {}

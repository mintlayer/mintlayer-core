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

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use common::chain::ChainConfig;

use crate::storage::storage_api::{
    ApiServerStorage, ApiServerStorageError, ApiServerTransactionRo, ApiServerTransactionRw,
    Transactional,
};

use super::ApiServerInMemoryStorage;

pub mod read;
pub mod write;

pub struct ApiServerInMemoryStorageTransactionalRo<'t> {
    transaction: tokio::sync::RwLockReadGuard<'t, ApiServerInMemoryStorage>,
}

impl<'t> ApiServerInMemoryStorageTransactionalRo<'t> {
    async fn new(storage: &'t TransactionalApiServerInMemoryStorage) -> Self {
        Self {
            transaction: storage.tx_ro().await,
        }
    }
}

#[async_trait::async_trait]
impl ApiServerTransactionRo for ApiServerInMemoryStorageTransactionalRo<'_> {
    async fn close(self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        Ok(())
    }
}

pub struct ApiServerInMemoryStorageTransactionalRw<'t> {
    transaction: RwLockWriteGuard<'t, ApiServerInMemoryStorage>,
    initial_data_before_tx: ApiServerInMemoryStorage,
}

impl<'t> ApiServerInMemoryStorageTransactionalRw<'t> {
    async fn new(storage: &'t mut TransactionalApiServerInMemoryStorage) -> Self {
        let transaction = storage.tx_rw().await;
        let initial_data_before_tx = transaction.clone();
        Self {
            transaction,
            initial_data_before_tx,
        }
    }
}

#[async_trait::async_trait]
impl ApiServerTransactionRw for ApiServerInMemoryStorageTransactionalRw<'_> {
    async fn commit(self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        Ok(())
    }

    async fn rollback(mut self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        // We restore the original data that was there when the transaction started
        std::mem::swap(&mut *self.transaction, &mut self.initial_data_before_tx);
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

    async fn tx_ro(&self) -> RwLockReadGuard<'_, ApiServerInMemoryStorage> {
        self.storage.read().await
    }

    async fn tx_rw(&mut self) -> RwLockWriteGuard<'_, ApiServerInMemoryStorage> {
        self.storage.write().await
    }

    pub async fn clone_storage(&self) -> Self {
        Self {
            storage: self.storage.read().await.clone().into(),
        }
    }
}

#[async_trait::async_trait]
impl<'tx> Transactional<'tx> for TransactionalApiServerInMemoryStorage {
    type TransactionRo = ApiServerInMemoryStorageTransactionalRo<'tx>;

    type TransactionRw = ApiServerInMemoryStorageTransactionalRw<'tx>;

    async fn transaction_ro<'db: 'tx>(
        &'db self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError> {
        Ok(ApiServerInMemoryStorageTransactionalRo::new(self).await)
    }

    async fn transaction_rw<'db: 'tx>(
        &'db mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError> {
        Ok(ApiServerInMemoryStorageTransactionalRw::new(self).await)
    }
}

impl ApiServerStorage for TransactionalApiServerInMemoryStorage {}

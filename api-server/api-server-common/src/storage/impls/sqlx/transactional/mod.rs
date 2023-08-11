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

use sqlx::Database;

use super::SqlxStorage;

pub struct TransactionalSqlxStorage<D: Database> {
    storage: SqlxStorage<D>,
}

impl<D: Database> TransactionalSqlxStorage<D> {
    pub fn new(storage: SqlxStorage<D>) -> Self {
        Self { storage }
    }

    pub async fn transaction_ro(&self) -> Result<SqlxTransactionRo<'_, D>, sqlx::Error> {
        let tx = self.storage.db_pool.begin().await?;
        let result = SqlxTransactionRo::new(tx, &self.storage);
        Ok(result)
    }

    pub async fn try_transaction_ro(
        &self,
    ) -> Result<Option<SqlxTransactionRo<'_, D>>, sqlx::Error> {
        let tx = self.storage.db_pool.try_begin().await?;
        let result = tx.map(|t| SqlxTransactionRo::new(t, &self.storage));
        Ok(result)
    }

    pub async fn transaction_rw(&mut self) -> Result<SqlxTransactionRw<'_, D>, sqlx::Error> {
        let tx = self.storage.db_pool.begin().await?;
        let result = SqlxTransactionRw::new(tx, &mut self.storage);
        Ok(result)
    }

    pub async fn try_transaction_rw(
        &mut self,
    ) -> Result<Option<SqlxTransactionRw<'_, D>>, sqlx::Error> {
        let tx = self.storage.db_pool.try_begin().await?;
        let result = tx.map(|t| SqlxTransactionRw::new(t, &mut self.storage));
        Ok(result)
    }
}

pub struct SqlxTransactionRo<'a, D: Database> {
    _tx: sqlx::Transaction<'a, D>,
    storage: &'a SqlxStorage<D>,
}

impl<'a, D: Database> SqlxTransactionRo<'a, D> {
    pub fn new(tx: sqlx::Transaction<'a, D>, storage: &'a SqlxStorage<D>) -> Self {
        Self { _tx: tx, storage }
    }

    pub fn storage(&self) -> &SqlxStorage<D> {
        self.storage
    }
}

pub struct SqlxTransactionRw<'a, D: Database> {
    tx: sqlx::Transaction<'a, D>,
    storage: &'a mut SqlxStorage<D>,
}

impl<'a, D: Database> SqlxTransactionRw<'a, D> {
    pub fn new(tx: sqlx::Transaction<'a, D>, storage: &'a mut SqlxStorage<D>) -> Self {
        Self { tx, storage }
    }

    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }

    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }

    pub fn storage_mut(&mut self) -> &mut SqlxStorage<D> {
        self.storage
    }

    pub fn storage(&self) -> &SqlxStorage<D> {
        self.storage
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::impls::CURRENT_STORAGE_VERSION;

    use super::*;

    #[tokio::test]
    async fn initialization() {
        let mut storage = SqlxStorage::from_sqlite_inmemory(5).await.unwrap().into_transactional();

        let mut db_tx = storage.transaction_rw().await.unwrap();

        let is_initialized = db_tx.storage().is_initialized().await.unwrap();
        assert!(!is_initialized);

        db_tx.storage_mut().initialize_database().await.unwrap();

        let is_initialized = db_tx.storage().is_initialized().await.unwrap();
        assert!(is_initialized);

        let version_option = db_tx.storage().get_storage_version().await.unwrap();
        assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);
    }
}

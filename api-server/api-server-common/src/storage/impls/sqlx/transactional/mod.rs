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

use super::{queries::QueryFromConnection, SqlxStorage};
use crate::storage::storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError};
use common::{
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use sqlx::{
    database::HasArguments, Acquire, ColumnIndex, Database, Executor, IntoArguments, Pool,
    Postgres, Sqlite,
};

pub struct TransactionalSqlxStorage<D: Database> {
    storage: SqlxStorage<D>,
}

impl<D: Database> TransactionalSqlxStorage<D> {
    pub fn new(storage: SqlxStorage<D>) -> Self {
        Self { storage }
    }

    pub async fn transaction_ro(&self) -> Result<SqlxTransactionRo<'_, D>, ApiServerStorageError> {
        let tx = self
            .storage
            .db_pool
            .begin()
            .await
            .map_err(|e| ApiServerStorageError::RoTxBeginFailed(e.to_string()))?;
        let result = SqlxTransactionRo::new(tx);
        Ok(result)
    }

    pub async fn try_transaction_ro(
        &self,
    ) -> Result<Option<SqlxTransactionRo<'_, D>>, ApiServerStorageError> {
        let tx = self
            .storage
            .db_pool
            .try_begin()
            .await
            .map_err(|e| ApiServerStorageError::RoTxBeginFailed(e.to_string()))?;

        let result = tx.map(|t| SqlxTransactionRo::new(t));
        Ok(result)
    }

    pub async fn transaction_rw(
        &mut self,
    ) -> Result<SqlxTransactionRw<'_, D>, ApiServerStorageError> {
        let tx = self
            .storage
            .db_pool
            .begin()
            .await
            .map_err(|e| ApiServerStorageError::RwTxBeginFailed(e.to_string()))?;

        let result = SqlxTransactionRw::new(tx);
        Ok(result)
    }

    pub async fn try_transaction_rw(
        &mut self,
    ) -> Result<Option<SqlxTransactionRw<'_, D>>, ApiServerStorageError> {
        let tx = self
            .storage
            .db_pool
            .try_begin()
            .await
            .map_err(|e| ApiServerStorageError::RwTxBeginFailed(e.to_string()))?;

        let result = tx.map(|t| SqlxTransactionRw::new(t));
        Ok(result)
    }
}

macro_rules! define_is_initialized {
    ($access_type:ident, $database:ty) => {
        impl<'a> $access_type<'a, $database> {
            pub async fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
                let conn =
                    self.tx.acquire().await.map_err(|e| {
                        ApiServerStorageError::AcquiringConnectionFailed(e.to_string())
                    })?;

                let is_initialized =
                    QueryFromConnection::<$database>::new(conn).is_initialized().await?;

                Ok(is_initialized)
            }
        }
    };
    ($database:ty) => {
        define_is_initialized!(SqlxTransactionRo, $database);
        define_is_initialized!(SqlxTransactionRw, $database);
    };
    () => {
        define_is_initialized!(Sqlite);
        define_is_initialized!(Postgres);
    };
}

macro_rules! define_database_access {
    ($access_type:ident) => {
        pub struct $access_type<'a, D: Database> {
            tx: sqlx::Transaction<'a, D>,
        }

        impl<'a, D: Database> $access_type<'a, D> {
            pub fn new(tx: sqlx::Transaction<'a, D>) -> Self {
                Self { tx }
            }

            pub async fn get_storage_version(
                &mut self,
            ) -> Result<Option<u32>, ApiServerStorageError>
            where
                for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
                for<'e> &'e mut D::Connection: Executor<'e>,
                for<'e> &'e Pool<D>: Executor<'e, Database = D>,
                for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
                usize: ColumnIndex<D::Row>,
                for<'e> Vec<u8>: sqlx::Decode<'e, D>,
                Vec<u8>: sqlx::Type<D>,
            {
                let conn =
                    self.tx.acquire().await.map_err(|e| {
                        ApiServerStorageError::AcquiringConnectionFailed(e.to_string())
                    })?;

                let version = QueryFromConnection::new(conn).get_storage_version().await?;

                Ok(version)
            }

            pub async fn get_main_chain_block_id(
                &mut self,
                block_height: BlockHeight,
            ) -> Result<Option<Id<Block>>, ApiServerStorageError>
            where
                for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
                for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
                usize: ColumnIndex<D::Row>,
                for<'e> Vec<u8>: sqlx::Decode<'e, D>,
                Vec<u8>: sqlx::Type<D>,
                for<'e> i64: sqlx::Encode<'e, D>,
                i64: sqlx::Type<D>,
            {
                let conn =
                    self.tx.acquire().await.map_err(|e| {
                        ApiServerStorageError::AcquiringConnectionFailed(e.to_string())
                    })?;

                let block_id =
                    QueryFromConnection::new(conn).get_main_chain_block_id(block_height).await?;

                Ok(block_id)
            }

            pub async fn get_block(
                &mut self,
                block_id: Id<Block>,
            ) -> Result<Option<Block>, ApiServerStorageError>
            where
                for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
                for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
                usize: ColumnIndex<D::Row>,
                for<'e> Vec<u8>: sqlx::Encode<'e, D>,
                Vec<u8>: sqlx::Type<D>,
                for<'e> Vec<u8>: sqlx::Decode<'e, D>,
            {
                let conn =
                    self.tx.acquire().await.map_err(|e| {
                        ApiServerStorageError::AcquiringConnectionFailed(e.to_string())
                    })?;

                let block = QueryFromConnection::new(conn).get_block(block_id).await?;

                Ok(block)
            }

            pub async fn get_transaction(
                &mut self,
                transaction_id: Id<Transaction>,
            ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError>
            where
                for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
                for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
                usize: ColumnIndex<D::Row>,
                for<'e> Vec<u8>: sqlx::Encode<'e, D>,
                Vec<u8>: sqlx::Type<D>,
                for<'e> Vec<u8>: sqlx::Decode<'e, D>,
            {
                let conn =
                    self.tx.acquire().await.map_err(|e| {
                        ApiServerStorageError::AcquiringConnectionFailed(e.to_string())
                    })?;

                let result = QueryFromConnection::new(conn).get_transaction(transaction_id).await?;

                Ok(result)
            }

            pub async fn get_block_aux_data(
                &mut self,
                block_id: Id<Block>,
            ) -> Result<Option<BlockAuxData>, ApiServerStorageError>
            where
                for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
                for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
                usize: ColumnIndex<D::Row>,
                for<'e> Vec<u8>: sqlx::Encode<'e, D>,
                Vec<u8>: sqlx::Type<D>,
                for<'e> Vec<u8>: sqlx::Decode<'e, D>,
            {
                let conn =
                    self.tx.acquire().await.map_err(|e| {
                        ApiServerStorageError::AcquiringConnectionFailed(e.to_string())
                    })?;

                let block_aux_data =
                    QueryFromConnection::new(conn).get_block_aux_data(block_id).await?;

                Ok(block_aux_data)
            }

            pub async fn get_best_block(
                &mut self,
            ) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError>
            where
                for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
                for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e, Database = D>,
                for<'e> &'e Pool<D>: Executor<'e, Database = D>,
                usize: ColumnIndex<<D as sqlx::Database>::Row>,
                Vec<u8>: sqlx::Type<D>,
                for<'e> Vec<u8>: sqlx::Decode<'e, D>,
            {
                let conn =
                    self.tx.acquire().await.map_err(|e| {
                        ApiServerStorageError::AcquiringConnectionFailed(e.to_string())
                    })?;

                let best = QueryFromConnection::new(conn).get_best_block().await?;

                Ok(best)
            }
        }
    };
    () => {
        define_database_access!(SqlxTransactionRo);
        define_database_access!(SqlxTransactionRw);
        define_is_initialized!();
    };
}

define_database_access!();

impl<'a, D: Database> SqlxTransactionRw<'a, D> {
    pub async fn commit(self) -> Result<(), ApiServerStorageError> {
        self.tx
            .commit()
            .await
            .map_err(|e| ApiServerStorageError::TxCommitFailed(e.to_string()))
    }

    pub async fn rollback(self) -> Result<(), ApiServerStorageError> {
        self.tx
            .rollback()
            .await
            .map_err(|e| ApiServerStorageError::TxRwRollbackFailed(e.to_string()))
    }

    #[allow(dead_code)]
    async fn create_tables(&mut self) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
    {
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn).create_tables().await?;

        Ok(())
    }

    pub async fn initialize_database(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> &'e str: sqlx::Encode<'e, D>,
        for<'e> &'e str: sqlx::Type<D>,
    {
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn).initialize_database(chain_config).await?;

        Ok(())
    }

    pub async fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        logging::log::debug!("Inserting block aux data with block_id {}", block_id);

        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn)
            .set_block_aux_data(block_id, block_aux_data)
            .await?;

        Ok(())
    }

    pub async fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> &'e str: sqlx::Encode<'e, D>,
        for<'e> &'e str: sqlx::Type<D>,
    {
        logging::log::debug!("Inserting best block with block_id {}", block_id);

        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn).set_best_block(block_height, block_id).await?;

        Ok(())
    }

    pub async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Option<Vec<u8>>: sqlx::Encode<'e, D>,
    {
        logging::log::debug!(
            "Inserting transaction with id {}, owned by block {:?}",
            transaction_id,
            owning_block
        );

        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn)
            .set_transaction(transaction_id, owning_block, transaction)
            .await?;

        Ok(())
    }

    pub async fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        logging::log::debug!("Inserting block with id: {:?}", block_id);

        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn).set_block(block_id, block).await?;

        Ok(())
    }

    pub async fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn).del_main_chain_block_id(block_height).await?;

        Ok(())
    }

    pub async fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        QueryFromConnection::new(conn)
            .set_main_chain_block_id(block_height, block_id)
            .await?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn is_initialized_internal(
        &mut self,
        query_str: &str,
    ) -> Result<bool, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> i64: sqlx::Decode<'e, D>,
        i64: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        let is_initialized =
            QueryFromConnection::new(conn).is_initialized_internal(query_str).await?;

        Ok(is_initialized)
    }
}

#[cfg(test)]
mod tests {
    use common::{chain::config::create_regtest, primitives::H256};
    use crypto::random::Rng;

    use crate::storage::impls::CURRENT_STORAGE_VERSION;

    use super::*;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    async fn init_ops(db_tx: &mut SqlxTransactionRw<'_, Sqlite>) {
        let chain_config = create_regtest();

        let is_initialized = db_tx.is_initialized().await.unwrap();
        assert!(!is_initialized);

        db_tx.initialize_database(&chain_config).await.unwrap();

        let is_initialized = db_tx.is_initialized().await.unwrap();
        assert!(is_initialized);

        let version_option = db_tx.get_storage_version().await.unwrap();
        assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);
    }

    #[tokio::test]
    async fn initialization_rollback() {
        let mut storage = SqlxStorage::from_sqlite_inmemory(5).await.unwrap().into_transactional();

        let mut db_tx = storage.transaction_rw().await.unwrap();

        init_ops(&mut db_tx).await;

        db_tx.rollback().await.unwrap();

        let mut db_tx = storage.transaction_ro().await.unwrap();
        let is_initialized = db_tx.is_initialized().await.unwrap();
        assert!(!is_initialized);
    }

    #[tokio::test]
    async fn initialization_commit() {
        let mut storage = SqlxStorage::from_sqlite_inmemory(5).await.unwrap().into_transactional();

        let mut db_tx = storage.transaction_rw().await.unwrap();

        init_ops(&mut db_tx).await;

        db_tx.commit().await.unwrap();

        let mut db_tx = storage.transaction_ro().await.unwrap();
        let version_option = db_tx.get_storage_version().await.unwrap();
        assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn block_height_id_commit(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = create_regtest();

        let mut storage = SqlxStorage::from_sqlite_inmemory(5).await.unwrap().into_transactional();

        let mut db_tx = storage.transaction_rw().await.unwrap();

        db_tx.initialize_database(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();

        let mut db_tx = storage.transaction_rw().await.unwrap();

        // Test setting mainchain block id and getting it back
        let height_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
        let height = height_u64.into();
        let random_block_id1 = Id::<Block>::new(H256::random_using(&mut rng));

        // Set then roll back
        {
            let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
            assert!(block_id.is_none());

            db_tx.set_main_chain_block_id(height, random_block_id1).await.unwrap();

            let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
            assert_eq!(block_id, Some(random_block_id1));
        }

        db_tx.rollback().await.unwrap();

        // We read, and it's not there because of the roll back
        {
            let mut db_tx = storage.transaction_ro().await.unwrap();
            let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
            assert_eq!(block_id, None);
        }

        // Set then commit
        let mut db_tx = storage.transaction_rw().await.unwrap();
        {
            let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
            assert!(block_id.is_none());

            db_tx.set_main_chain_block_id(height, random_block_id1).await.unwrap();

            let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
            assert_eq!(block_id, Some(random_block_id1));
        }
        db_tx.commit().await.unwrap();

        // We read, and it's there because we committed
        {
            let mut db_tx = storage.transaction_ro().await.unwrap();
            let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
            assert_eq!(block_id, Some(random_block_id1));
        }
    }

    // TODO: test the remaining set/get functions
}

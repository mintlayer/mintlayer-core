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

use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use sqlx::{database::HasArguments, Acquire, ColumnIndex, Database, Executor, IntoArguments, Pool};

use crate::storage::storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError};

use super::{queries::QueryFromConnection, SqlxStorage};

pub struct TransactionalSqlxStorage<D: Database> {
    storage: SqlxStorage<D>,
}

impl<D: Database> TransactionalSqlxStorage<D> {
    pub fn new(storage: SqlxStorage<D>) -> Self {
        Self { storage }
    }

    pub async fn transaction_ro(&self) -> Result<SqlxTransactionRo<'_, D>, sqlx::Error> {
        let tx = self.storage.db_pool.begin().await?;
        let result = SqlxTransactionRo::new(tx);
        Ok(result)
    }

    pub async fn try_transaction_ro(
        &self,
    ) -> Result<Option<SqlxTransactionRo<'_, D>>, sqlx::Error> {
        let tx = self.storage.db_pool.try_begin().await?;
        let result = tx.map(|t| SqlxTransactionRo::new(t));
        Ok(result)
    }

    pub async fn transaction_rw(&mut self) -> Result<SqlxTransactionRw<'_, D>, sqlx::Error> {
        let tx = self.storage.db_pool.begin().await?;
        let result = SqlxTransactionRw::new(tx);
        Ok(result)
    }

    pub async fn try_transaction_rw(
        &mut self,
    ) -> Result<Option<SqlxTransactionRw<'_, D>>, sqlx::Error> {
        let tx = self.storage.db_pool.try_begin().await?;
        let result = tx.map(|t| SqlxTransactionRw::new(t));
        Ok(result)
    }
}

pub struct SqlxTransactionRo<'a, D: Database> {
    tx: sqlx::Transaction<'a, D>,
}

impl<'a, D: Database> SqlxTransactionRo<'a, D> {
    pub fn new(tx: sqlx::Transaction<'a, D>) -> Self {
        Self { tx }
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

    pub async fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        let block_id = QueryFromConnection::new(conn).get_main_chain_block_id(block_height).await?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        let block_aux_data = QueryFromConnection::new(conn).get_block_aux_data(block_id).await?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        let best = QueryFromConnection::new(conn).get_best_block().await?;

        Ok(best)
    }
}

pub struct SqlxTransactionRw<'a, D: Database> {
    tx: sqlx::Transaction<'a, D>,
}

impl<'a, D: Database> SqlxTransactionRw<'a, D> {
    pub fn new(tx: sqlx::Transaction<'a, D>) -> Self {
        Self { tx }
    }

    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }

    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
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

    pub async fn initialize_database(&mut self) -> Result<(), ApiServerStorageError>
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

        QueryFromConnection::new(conn).initialize_database().await?;

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

    pub async fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        let block_id = QueryFromConnection::new(conn).get_main_chain_block_id(block_height).await?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        let block_aux_data = QueryFromConnection::new(conn).get_block_aux_data(block_id).await?;

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
        let conn = self
            .tx
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;

        let best = QueryFromConnection::new(conn).get_best_block().await?;

        Ok(best)
    }
}

#[cfg(test)]
mod tests {
    // use crate::storage::impls::CURRENT_STORAGE_VERSION;

    // use super::*;

    // #[tokio::test]
    // async fn initialization() {
    //     let mut storage = SqlxStorage::from_sqlite_inmemory(5).await.unwrap().into_transactional();

    //     let mut db_tx = storage.transaction_rw().await.unwrap();

    //     let is_initialized = db_tx.is_initialized().await.unwrap();
    //     assert!(!is_initialized);

    //     db_tx.storage_mut().initialize_database().await.unwrap();

    //     let is_initialized = db_tx.storage().is_initialized().await.unwrap();
    //     assert!(is_initialized);

    //     let version_option = db_tx.storage().get_storage_version().await.unwrap();
    //     assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);
    // }
}

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

pub mod transactional;

mod queries;

use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use sqlx::{
    database::HasArguments, ColumnIndex, Database, Executor, IntoArguments, Pool, Postgres, Sqlite,
};

use crate::storage::{
    impls::sqlx::queries::QueryFromConnection,
    storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError},
};

pub struct SqlxStorage<D: Database> {
    db_pool: Pool<D>,
}

impl SqlxStorage<Sqlite> {
    pub async fn from_sqlite_inmemory(max_connections: u32) -> Result<Self, ApiServerStorageError> {
        let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(Self { db_pool })
    }

    fn get_table_exists_query(table_name: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{}'",
            table_name
        )
    }

    pub async fn is_initialized(&self) -> Result<bool, ApiServerStorageError> {
        let query_str = Self::get_table_exists_query("ml_misc_data");
        let is_initialized = self.is_initialized_internal(&query_str).await?;
        Ok(is_initialized)
    }
}

impl SqlxStorage<Postgres> {
    fn get_table_exists_query(table_name: &str) -> String {
        format!(
            "SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_name = '{}'
        ) THEN 1 ELSE 0 END AS count;",
            table_name
        )
    }

    pub async fn is_initialized(&self) -> Result<bool, ApiServerStorageError> {
        let query_str = Self::get_table_exists_query("ml_misc_data");
        let is_initialized = self.is_initialized_internal(&query_str).await?;
        Ok(is_initialized)
    }
}

impl<D> SqlxStorage<D>
where
    D: Database,
{
    pub fn into_transactional(self) -> transactional::TransactionalSqlxStorage<D> {
        transactional::TransactionalSqlxStorage::new(self)
    }

    pub fn new(db_pool: Pool<D>) -> Result<Self, ApiServerStorageError> {
        Ok(Self { db_pool })
    }

    async fn is_initialized_internal(&self, query_str: &str) -> Result<bool, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> i64: sqlx::Decode<'e, D>,
        i64: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        let rows: (i64,) = sqlx::query_as(query_str)
            .fetch_one(&self.db_pool)
            .await
            .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        if rows.0 == 0 {
            return Ok(false);
        }

        let version = self.get_storage_version().await?;

        let version = match version {
            Some(v) => v,
            None => return Ok(false),
        };

        logging::log::info!("Found database version: {version}");

        Ok(true)
    }

    pub async fn get_storage_version(&self) -> Result<Option<u32>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        let version = QueryFromConnection::new(conn).get_storage_version().await?;

        Ok(version)
    }

    #[allow(dead_code)]
    async fn create_tables(&self) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
    {
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn).create_tables().await?;

        Ok(())
    }

    pub async fn initialize_database(&self) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> &'e str: sqlx::Encode<'e, D>,
        for<'e> &'e str: sqlx::Type<D>,
    {
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn).initialize_database().await?;

        Ok(())
    }

    pub async fn get_main_chain_block_id(
        &self,
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
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        let block_id = QueryFromConnection::new(conn).get_main_chain_block_id(block_height).await?;

        Ok(block_id)
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
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn)
            .set_main_chain_block_id(block_height, block_id)
            .await?;

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
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn).del_main_chain_block_id(block_height).await?;

        Ok(())
    }

    pub async fn get_block(
        &self,
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
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        let block = QueryFromConnection::new(conn).get_block(block_id).await?;

        Ok(block)
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

        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn).set_block(block_id, block).await?;

        Ok(())
    }

    pub async fn get_transaction(
        &self,
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
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        let result = QueryFromConnection::new(conn).get_transaction(transaction_id).await?;

        Ok(result)
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

        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn)
            .set_transaction(transaction_id, owning_block, transaction)
            .await?;

        Ok(())
    }

    pub async fn get_block_aux_data(
        &self,
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
        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        let block_aux_data = QueryFromConnection::new(conn).get_block_aux_data(block_id).await?;

        Ok(block_aux_data)
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

        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn)
            .set_block_aux_data(block_id, block_aux_data)
            .await?;

        Ok(())
    }

    pub async fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
    {
        let mut pool = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        let best = QueryFromConnection::new(conn).get_best_block().await?;

        Ok(best)
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

        let mut pool: sqlx::pool::PoolConnection<D> = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        let conn = pool.as_mut();

        QueryFromConnection::new(conn).set_best_block(block_height, block_id).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chainstate_test_framework::{TestFramework, TransactionBuilder};
    use common::{
        chain::{signature::inputsig::InputWitness, OutPointSourceId, TxInput, UtxoOutPoint},
        primitives::{Idable, H256},
    };

    use crate::storage::impls::CURRENT_STORAGE_VERSION;

    use super::*;
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    pub fn empty_witness(rng: &mut impl Rng) -> InputWitness {
        use crypto::random::SliceRandom;
        let mut msg: Vec<u8> = (1..100).collect();
        msg.shuffle(rng);
        InputWitness::NoSignature(Some(msg))
    }

    #[tokio::test]
    async fn initialization() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let storage = SqlxStorage::new(pool).unwrap();

        storage.get_storage_version().await.unwrap_err();

        let is_initialized = storage.is_initialized().await.unwrap();
        assert!(!is_initialized);

        storage.initialize_database().await.unwrap();

        let is_initialized = storage.is_initialized().await.unwrap();
        assert!(is_initialized);

        let version_option = storage.get_storage_version().await.unwrap();
        assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_get(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let mut storage = SqlxStorage::new(pool).unwrap();

        storage.get_storage_version().await.unwrap_err();

        let is_initialized = storage.is_initialized().await.unwrap();
        assert!(!is_initialized);

        storage.initialize_database().await.unwrap();

        let is_initialized = storage.is_initialized().await.unwrap();
        assert!(is_initialized);

        let version_option = storage.get_storage_version().await.unwrap();
        assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);

        // Test setting mainchain block id and getting it back
        {
            let height_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
            let height = height_u64.into();

            let block_id = storage.get_main_chain_block_id(height).await.unwrap();
            assert!(block_id.is_none());

            let random_block_id1 = Id::<Block>::new(H256::random_using(&mut rng));
            storage.set_main_chain_block_id(height, random_block_id1).await.unwrap();

            let block_id = storage.get_main_chain_block_id(height).await.unwrap();
            assert_eq!(block_id, Some(random_block_id1));

            let random_block_id2 = Id::<Block>::new(H256::random_using(&mut rng));
            storage.set_main_chain_block_id(height, random_block_id2).await.unwrap();

            let block_id = storage.get_main_chain_block_id(height).await.unwrap();
            assert_eq!(block_id, Some(random_block_id2));

            // Now delete the block id, then get it, and it won't be there
            storage.del_main_chain_block_id(height).await.unwrap();
            let block_id = storage.get_main_chain_block_id(height).await.unwrap();
            assert!(block_id.is_none());

            // Delete again, as deleting non-existing data is OK
            storage.del_main_chain_block_id(height).await.unwrap();
            storage.del_main_chain_block_id(height).await.unwrap();
        }

        // Test setting/getting blocks
        {
            {
                let random_block_id: Id<Block> = Id::<Block>::new(H256::random_using(&mut rng));
                let block = storage.get_block(random_block_id).await.unwrap();
                assert!(block.is_none());
            }
            // Create a test framework and blocks

            let mut test_framework = TestFramework::builder(&mut rng).build();
            let chain_config = test_framework.chain_config().clone();
            let genesis_id = chain_config.genesis_block_id();
            test_framework.create_chain(&genesis_id, 10, &mut rng).unwrap();

            let block_id1 =
                test_framework.block_id(1).classify(&chain_config).chain_block_id().unwrap();
            let block1 = test_framework.block(block_id1);

            {
                let block_id = storage.get_block(block_id1).await.unwrap();
                assert!(block_id.is_none());

                storage.set_block(block_id1, &block1).await.unwrap();

                let block = storage.get_block(block_id1).await.unwrap();
                assert_eq!(block, Some(block1));
            }
        }

        // Test setting/getting transactions
        {
            let random_tx_id: Id<Transaction> =
                Id::<Transaction>::new(H256::random_using(&mut rng));
            let tx = storage.get_transaction(random_tx_id).await.unwrap();
            assert!(tx.is_none());

            let owning_block1 = Id::<Block>::new(H256::random_using(&mut rng));
            let tx1: SignedTransaction = TransactionBuilder::new()
                .add_input(
                    TxInput::Utxo(UtxoOutPoint::new(
                        OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(
                            &mut rng,
                        ))),
                        0,
                    )),
                    empty_witness(&mut rng),
                )
                .build();

            // before storage
            let tx_and_block_id =
                storage.get_transaction(tx1.transaction().get_id()).await.unwrap();
            assert!(tx_and_block_id.is_none());

            // Set without owning block
            {
                storage.set_transaction(tx1.transaction().get_id(), None, &tx1).await.unwrap();

                let tx_and_block_id =
                    storage.get_transaction(tx1.transaction().get_id()).await.unwrap();
                assert!(tx_and_block_id.is_some());

                let (owning_block, tx_retrieved) = tx_and_block_id.unwrap();
                assert!(owning_block.is_none());
                assert_eq!(tx_retrieved, tx1);
            }

            // Set with owning block
            {
                storage
                    .set_transaction(tx1.transaction().get_id(), Some(owning_block1), &tx1)
                    .await
                    .unwrap();

                let tx_and_block_id =
                    storage.get_transaction(tx1.transaction().get_id()).await.unwrap();
                assert!(tx_and_block_id.is_some());

                let (owning_block, tx_retrieved) = tx_and_block_id.unwrap();
                assert_eq!(owning_block, Some(owning_block1));
                assert_eq!(tx_retrieved, tx1);
            }
        }

        // Test setting/getting block aux data
        {
            let random_block_id: Id<Block> = Id::<Block>::new(H256::random_using(&mut rng));
            let block = storage.get_block_aux_data(random_block_id).await.unwrap();
            assert!(block.is_none());

            let height1_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
            let height1 = height1_u64.into();
            let aux_data1 = BlockAuxData::new(random_block_id, height1);
            storage.set_block_aux_data(random_block_id, &aux_data1).await.unwrap();

            let retrieved_aux_data = storage.get_block_aux_data(random_block_id).await.unwrap();
            assert_eq!(retrieved_aux_data, Some(aux_data1));

            // Test overwrite
            let height2_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
            let height2 = height2_u64.into();
            let aux_data2 = BlockAuxData::new(random_block_id, height2);
            storage.set_block_aux_data(random_block_id, &aux_data2).await.unwrap();

            let retrieved_aux_data = storage.get_block_aux_data(random_block_id).await.unwrap();
            assert_eq!(retrieved_aux_data, Some(aux_data2));
        }

        // Test setting/getting best block
        {
            // Set once then get best block
            {
                let height1_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
                let height1 = height1_u64.into();
                let random_block_id1 = Id::<Block>::new(H256::random_using(&mut rng));

                storage.set_best_block(height1, random_block_id1.into()).await.unwrap();

                let (retrieved_best_height, retrieved_best_id) =
                    storage.get_best_block().await.unwrap();

                assert_eq!(height1, retrieved_best_height);
                assert_eq!(random_block_id1, retrieved_best_id);
            }

            // Set again to test overwrite
            {
                let height2_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
                let height2 = height2_u64.into();
                let random_block_id2 = Id::<Block>::new(H256::random_using(&mut rng));

                storage.set_best_block(height2, random_block_id2.into()).await.unwrap();

                let (retrieved_best_height, retrieved_best_id) =
                    storage.get_best_block().await.unwrap();

                assert_eq!(height2, retrieved_best_height);
                assert_eq!(random_block_id2, retrieved_best_id);
            }
        }
    }

    #[tokio::test]
    async fn basic_sqlx_sqlite_inmemory() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE some_table (
            id INTEGER AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(255) NOT NULL,
            last_name TEXT NOT NULL,
            age INTEGER NOT NULL
          );
          ",
        )
        .execute(&pool)
        .await
        .unwrap();

        let rows: (i64,) =
            sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) as count_pet FROM some_table;")
                .fetch_one(&pool)
                .await
                .unwrap();

        // No rows
        assert_eq!(rows.0, 0);

        // Insert row to the table
        sqlx::query("INSERT INTO some_table (first_name, last_name, age) VALUES (?, ?, ?)")
            .bind("Richard")
            .bind("Roe")
            .bind(55)
            .execute(&pool)
            .await
            .unwrap();

        let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) as count_pet FROM some_table;")
            .fetch_one(&pool)
            .await
            .unwrap();

        // After insertion, there's one row
        assert_eq!(rows.0, 1);
    }

    #[tokio::test]
    async fn uninitialized() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let storage = SqlxStorage::new(pool).unwrap();

        storage.create_tables().await.unwrap();

        let version_option = storage.get_storage_version().await.unwrap();
        assert!(version_option.is_none());

        let is_initialized = storage.is_initialized().await.unwrap();

        assert!(!is_initialized);
    }
}

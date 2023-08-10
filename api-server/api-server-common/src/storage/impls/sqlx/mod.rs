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
    chain::Block,
    primitives::{BlockHeight, Id},
};
use serialization::{DecodeAll, Encode};
use sqlx::{
    database::HasArguments, ColumnIndex, Database, Executor, IntoArguments, Pool, Postgres, Sqlite,
};

use crate::storage::storage_api::ApiServerStorageError;

use super::CURRENT_STORAGE_VERSION;

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
        let query_str = Self::get_table_exists_query("misc_data");
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
        let query_str = Self::get_table_exists_query("misc_data");
        let is_initialized = self.is_initialized_internal(&query_str).await?;
        Ok(is_initialized)
    }
}

impl<D> SqlxStorage<D>
where
    D: Database,
{
    pub fn new(db_pool: Pool<D>) -> Result<Self, ApiServerStorageError> {
        Ok(Self { db_pool })
    }

    async fn is_initialized_internal(&self, query_str: &str) -> Result<bool, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
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
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        let data: Option<(Vec<u8>,)> =
            sqlx::query_as::<_, _>("SELECT value FROM misc_data WHERE name = 'version';")
                .fetch_optional(&self.db_pool)
                .await
                .map_err(|e: sqlx::Error| {
                    ApiServerStorageError::LowLevelStorageError(e.to_string())
                })?;

        let data = match data {
            Some(d) => d,
            None => return Ok(None),
        };

        let version = u32::decode_all(&mut data.0.as_slice()).map_err(|e| {
            ApiServerStorageError::InvalidInitializedState(format!(
                "Version deserialization failed: {}",
                e
            ))
        })?;

        Ok(Some(version))
    }

    async fn create_tables(&self) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
    {
        sqlx::query(
            "CREATE TABLE misc_data (
                  id INTEGER AUTO_INCREMENT PRIMARY KEY,
                  name TEXT NOT NULL,
                  value BLOB NOT NULL
            );",
        )
        .execute(&self.db_pool)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE main_chain_blocks (
                  block_height bigint PRIMARY KEY,
                  block_id BLOB NOT NULL
            );",
        )
        .execute(&self.db_pool)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE blocks (
                  block_id BLOB PRIMARY KEY,
                  block BLOB NOT NULL
            );",
        )
        .execute(&self.db_pool)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn initialize_database(&self) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> String: sqlx::Encode<'e, D>,
        String: sqlx::Type<D>,
    {
        self.create_tables().await?;

        // Insert row to the table
        sqlx::query("INSERT INTO misc_data (name, value) VALUES (?, ?)")
            .bind("version".to_string())
            .bind(CURRENT_STORAGE_VERSION.encode())
            .execute(&self.db_pool)
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        Ok(())
    }

    fn block_height_to_sqlx_friendly(block_height: BlockHeight) -> i64 {
        // sqlx doesn't like u64, so we have to convert it to i64, and given BlockDistance limitations, it's OK.
        block_height
            .into_int()
            .try_into()
            .unwrap_or_else(|e| panic!("Invalid block height: {e}"))
    }

    pub async fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let height = Self::block_height_to_sqlx_friendly(block_height);

        let row: Option<(Vec<u8>,)> = sqlx::query_as::<_, _>(
            "SELECT block_id FROM main_chain_blocks WHERE block_height = ?;",
        )
        .bind(height)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d.0,
            None => return Ok(None),
        };

        let block_id = Id::<Block>::decode_all(&mut data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Block id deserialization failed: {}",
                e
            ))
        })?;

        Ok(Some(block_id))
    }

    pub async fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let height = Self::block_height_to_sqlx_friendly(block_height);

        logging::log::debug!("Inserting block id: {:?} for height: {}", block_id, height);

        sqlx::query(
            "INSERT INTO main_chain_blocks (block_height, block_id) VALUES ($1, $2)
                ON CONFLICT (block_height) DO UPDATE
                SET block_id = $2;",
        )
        .bind(height)
        .bind(block_id.encode())
        .execute(&self.db_pool)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let height = Self::block_height_to_sqlx_friendly(block_height);

        sqlx::query(
            "DELETE FROM main_chain_blocks
            WHERE block_height = $1;",
        )
        .bind(height)
        .execute(&self.db_pool)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_block(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
    {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT block FROM blocks WHERE block_id = ?;")
                .bind(block_id.encode())
                .fetch_optional(&self.db_pool)
                .await
                .map_err(|e: sqlx::Error| {
                    ApiServerStorageError::LowLevelStorageError(e.to_string())
                })?;

        let data = match row {
            Some(d) => d.0,
            None => return Ok(None),
        };

        let block = Block::decode_all(&mut data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Block deserialization failed: {}",
                e
            ))
        })?;

        Ok(Some(block))
    }

    pub async fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        logging::log::debug!("Inserting block with id: {:?}", block_id);

        sqlx::query(
            "INSERT INTO blocks (block_id, block) VALUES ($1, $2)
                ON CONFLICT (block_id) DO UPDATE
                SET block = $2;",
        )
        .bind(block_id.encode())
        .bind(block.encode())
        .execute(&self.db_pool)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chainstate_test_framework::TestFramework;
    use common::primitives::H256;

    use super::*;
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

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
                let block_id = storage.get_block(random_block_id).await.unwrap();
                assert!(block_id.is_none());
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
    }

    #[tokio::test]
    async fn basic_sqlx_sqlite_inmemory() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE misc_data (
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
            sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) as count_pet FROM misc_data;")
                .fetch_one(&pool)
                .await
                .unwrap();

        // No rows
        assert_eq!(rows.0, 0);

        // Insert row to the table
        sqlx::query("INSERT INTO misc_data (first_name, last_name, age) VALUES (?, ?, ?)")
            .bind("Richard")
            .bind("Roe")
            .bind(55)
            .execute(&pool)
            .await
            .unwrap();

        let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) as count_pet FROM misc_data;")
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

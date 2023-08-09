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

use serialization::{DecodeAll, Encode};
use sqlx::{database::HasArguments, ColumnIndex, Database, Executor, IntoArguments, Pool, Sqlite};

use crate::storage::storage_api::ApiStorageError;

use super::CURRENT_STORAGE_VERSION;

pub struct SqlxStorage<D: Database> {
    #[allow(dead_code)]
    db_pool: Pool<D>,
}

impl SqlxStorage<Sqlite> {
    pub async fn from_sqlite_inmemory(max_connections: u32) -> Result<Self, ApiStorageError> {
        let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| ApiStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(Self { db_pool })
    }
}

impl<D> SqlxStorage<D>
where
    D: Database,
{
    pub fn new(db_pool: Pool<D>) -> Result<Self, ApiStorageError> {
        Ok(Self { db_pool })
    }

    pub async fn is_initialized(&self) -> Result<bool, ApiStorageError>
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
        let rows: (i64,) = sqlx::query_as::<_, _>("SELECT COUNT(*) as table_count FROM misc_data;")
            .fetch_one(&self.db_pool)
            .await
            .map_err(|e: sqlx::Error| e.to_string())
            .unwrap();

        if rows.0 == 0 {
            return Ok(false);
        }

        let data: (Vec<u8>,) =
            sqlx::query_as::<_, _>("SELECT value FROM misc_data WHERE name = 'version';")
                .fetch_one(&self.db_pool)
                .await
                .map_err(|e: sqlx::Error| ApiStorageError::LowLevelStorageError(e.to_string()))?;

        let version = u32::decode_all(&mut data.0.as_slice()).map_err(|e| {
            ApiStorageError::InvalidInitializedState(format!(
                "Version deserialization failed: {}",
                e
            ))
        })?;

        logging::log::info!("Found database version: {version}");

        Ok(true)
    }

    pub async fn get_storage_version(&self) -> Result<Option<u32>, ApiStorageError>
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
                .map_err(|e: sqlx::Error| ApiStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match data {
            Some(d) => d,
            None => return Ok(None),
        };

        let version = u32::decode_all(&mut data.0.as_slice()).map_err(|e| {
            ApiStorageError::InvalidInitializedState(format!(
                "Version deserialization failed: {}",
                e
            ))
        })?;

        Ok(Some(version))
    }

    async fn create_tables(&self) -> Result<(), ApiStorageError>
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
        .map_err(|e| ApiStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn initialize_database(&self) -> Result<(), ApiStorageError>
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
            .map_err(|e| ApiStorageError::InitializationError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

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

    #[tokio::test]
    async fn initialization() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let storage = SqlxStorage::new(pool).unwrap();

        storage.get_storage_version().await.unwrap_err();

        storage.initialize_database().await.unwrap();

        let is_initialized = storage.is_initialized().await.unwrap();

        assert!(is_initialized);

        let version_option = storage.get_storage_version().await.unwrap();
        assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);
    }
}

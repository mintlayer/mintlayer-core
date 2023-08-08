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

use sqlx::{Database, Pool};

use crate::storage::storage_api::ApiStorageError;

pub struct SqlxStorage<D: Database> {
    #[allow(dead_code)]
    db_pool: Pool<D>,
}

impl<D: Database> SqlxStorage<D> {
    pub fn new(db_pool: Pool<D>) -> Result<Self, ApiStorageError> {
        Ok(Self { db_pool })
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn basic_sqlx_sqlite_inmemory() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE students (
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

        let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) as count_pet FROM students;")
            .fetch_one(&pool)
            .await
            .unwrap();

        // No rows
        assert_eq!(rows.0, 0);

        // Insert row to the table
        sqlx::query("INSERT INTO students (first_name, last_name, age) VALUES (?, ?, ?)")
            .bind("Richard")
            .bind("Roe")
            .bind(55)
            .execute(&pool)
            .await
            .unwrap();

        let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) as count_pet FROM students;")
            .fetch_one(&pool)
            .await
            .unwrap();

        // After insertion, there's one row
        assert_eq!(rows.0, 1);
    }
}

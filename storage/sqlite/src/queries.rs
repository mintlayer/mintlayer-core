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

use storage_core::{DbDesc, DbIndex};

/// Return the prefix of the database key/value tables
#[inline]
pub fn db_table_name(idx: usize) -> String {
    format!("db_{idx}")
}

/// Returns an SQL query to create a table
#[inline]
pub fn create_table_query(table_name: &String) -> String {
    format!("CREATE TABLE {table_name}(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)")
}

/// SQL queries that are customized per an individual key/value database
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct SqliteQuery {
    /// Used for the get operation
    pub get_query: String,
    /// Used for the prefix iter operation
    pub prefix_iter_query: String,
    /// Used for the put operation
    pub put_query: String,
    /// Used for the delete operation
    pub delete_query: String,
}

/// Holds typical SQL queries like for retrieving, inserting, deleting key/values
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct SqliteQueries(Vec<SqliteQuery>);

impl SqliteQueries {
    pub fn new(desc: &DbDesc) -> Self {
        // Set up all the databases
        let queries = (0..desc.len())
            .map(|i| SqliteQuery {
                get_query: format!("SELECT value FROM db_{i} WHERE key = ?"),
                prefix_iter_query: format!("SELECT key, value FROM db_{i} ORDER BY key"),
                put_query: format!("INSERT or REPLACE into db_{i} values(?, ?)"),
                delete_query: format!("DELETE FROM db_{i} WHERE key = ?"),
            })
            .collect();

        Self(queries)
    }
}

impl std::ops::Index<DbIndex> for SqliteQueries {
    type Output = SqliteQuery;

    fn index(&self, index: DbIndex) -> &Self::Output {
        &self.0[index.get()]
    }
}

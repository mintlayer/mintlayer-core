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

extern crate core;

mod error;
mod queries;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::borrow::Cow;
use std::cmp::max;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use crate::queries::SqliteQueries;
use error::process_sqlite_error;
use storage_core::{backend, Data, DbDesc, DbMapId};
use utils::shallow_clone::ShallowClone;
use utils::sync::Arc;

/// Sqlite iterator over entries with given key prefix
pub struct PrefixIter {
    /// Underlying iterator
    iter: std::vec::IntoIter<(Vec<u8>, Vec<u8>)>,

    /// Prefix to iterate over
    prefix: Data,
}

impl PrefixIter {
    fn new(iter: std::vec::IntoIter<(Vec<u8>, Vec<u8>)>, prefix: Data) -> Self {
        PrefixIter { iter, prefix }
    }
}

impl Iterator for PrefixIter {
    type Item = (Data, Data);

    fn next(&mut self) -> Option<Self::Item> {
        let kv = self.iter.next()?;
        utils::ensure!(kv.0.starts_with(&self.prefix));
        Some(kv)
    }
}

pub struct DbTx<'m> {
    connection: MutexGuard<'m, Connection>,
    queries: &'m SqliteQueries,
}

impl<'m> DbTx<'m> {
    fn start_transaction(sqlite: &'m SqliteImpl) -> storage_core::Result<Self> {
        let connection = sqlite
            .0
            .connection
            .lock()
            .map_err(|e| storage_core::error::Fatal::InternalError(e.to_string()))?;
        let tx = DbTx {
            connection,
            queries: &sqlite.0.queries,
        };
        tx.connection.execute("BEGIN TRANSACTION", ()).map_err(process_sqlite_error)?;
        Ok(tx)
    }

    fn commit_transaction(&self) -> storage_core::Result<()> {
        let _res = self
            .connection
            .execute("COMMIT TRANSACTION", ())
            .map_err(process_sqlite_error)?;
        Ok(())
    }
}

impl Drop for DbTx<'_> {
    fn drop(&mut self) {
        if self.connection.is_autocommit() {
            return;
        }

        let res = self.connection.execute("ROLLBACK TRANSACTION", ());
        if let Err(err) = res {
            logging::log::error!("Error: transaction rollback failed: {}", err);
        }
    }
}

impl backend::ReadOps for DbTx<'_> {
    type PrefixIter<'i> = PrefixIter where Self: 'i;

    fn get(&self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<Option<Cow<[u8]>>> {
        let mut stmt = self
            .connection
            .prepare_cached(self.queries[map_id].get_query.as_str())
            .map_err(process_sqlite_error)?;

        let params = (key,);
        let res = stmt
            .query_row(params, |row| row.get::<usize, Vec<u8>>(0))
            .optional()
            .map_err(process_sqlite_error)?;
        let res = res.map(|v| v.into());
        Ok(res)
    }

    fn prefix_iter(
        &self,
        map_id: DbMapId,
        prefix: Data,
    ) -> storage_core::Result<Self::PrefixIter<'_>> {
        // TODO check if prefix.is_empty()
        // TODO Perform the filtering in the SQL query itself
        let mut stmt = self
            .connection
            .prepare_cached(self.queries[map_id].prefix_iter_query.as_str())
            .map_err(process_sqlite_error)?;

        let mut rows = stmt.query(()).map_err(process_sqlite_error)?;

        // TODO Move the statement/rows in to the PrefixIter
        let mut kv = Vec::new();
        while let Some(row) = rows.next().map_err(process_sqlite_error)? {
            let key = row.get::<usize, Vec<u8>>(0).map_err(process_sqlite_error)?;
            if key.starts_with(&prefix) {
                let value = row.get::<usize, Vec<u8>>(1).map_err(process_sqlite_error)?;
                kv.push((key, value));
            }
        }
        let kv_iter = kv.into_iter();

        Ok(PrefixIter::new(kv_iter, prefix))
    }
}

impl backend::WriteOps for DbTx<'_> {
    fn put(&mut self, map_id: DbMapId, key: Data, val: Data) -> storage_core::Result<()> {
        let mut stmt = self
            .connection
            .prepare_cached(self.queries[map_id].put_query.as_str())
            .map_err(process_sqlite_error)?;

        let params = (key, val);
        let _res = stmt.execute(params).map_err(process_sqlite_error)?;

        Ok(())
    }

    fn del(&mut self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<()> {
        let mut stmt = self
            .connection
            .prepare_cached(self.queries[map_id].delete_query.as_str())
            .map_err(process_sqlite_error)?;

        let params = (key,);
        let _res = stmt.execute(params).map_err(process_sqlite_error)?;

        Ok(())
    }
}

impl backend::TxRo for DbTx<'_> {}

impl backend::TxRw for DbTx<'_> {
    fn commit(self) -> storage_core::Result<()> {
        self.commit_transaction()
    }
}

/// Struct that holds the details for an Sqlite connection
pub struct SqliteConnection {
    /// Handle to an Sqlite database connection
    connection: Mutex<Connection>,

    /// List of sql queries
    queries: SqliteQueries,
}

#[derive(Clone)]
pub struct SqliteImpl(Arc<SqliteConnection>);

impl SqliteImpl {
    /// Start a transaction using the low-level method provided
    fn start_transaction(&self) -> storage_core::Result<DbTx<'_>> {
        DbTx::start_transaction(self)
    }
}

impl ShallowClone for SqliteImpl {
    fn shallow_clone(&self) -> Self {
        Self(self.0.shallow_clone())
    }
}

impl backend::BackendImpl for SqliteImpl {
    type TxRo<'a> = DbTx<'a>;

    type TxRw<'a> = DbTx<'a>;

    fn transaction_ro(&self) -> storage_core::Result<Self::TxRo<'_>> {
        self.start_transaction()
    }

    fn transaction_rw(&self, _size: Option<usize>) -> storage_core::Result<Self::TxRw<'_>> {
        self.start_transaction()
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
enum SqliteStorageMode {
    InMemory,
    File(PathBuf),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Sqlite {
    backend: SqliteStorageMode,
}

impl Sqlite {
    pub fn new_in_memory() -> Self {
        Self {
            backend: SqliteStorageMode::InMemory,
        }
    }

    /// New Sqlite database backend
    pub fn new(path: PathBuf) -> Self {
        Self {
            backend: SqliteStorageMode::File(path),
        }
    }

    fn open_db(self, desc: DbDesc) -> rusqlite::Result<Connection> {
        let flags = OpenFlags::from_iter([
            OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            OpenFlags::SQLITE_OPEN_CREATE,
        ]);

        let connection = match self.backend {
            SqliteStorageMode::InMemory => Connection::open_in_memory_with_flags(flags)?,
            SqliteStorageMode::File(path) => Connection::open_with_flags(path, flags)?,
        };

        // Set the locking mode to exclusive
        connection.pragma_update(None, "locking_mode", "exclusive")?;

        // Begin a transaction to acquire the exclusive lock
        connection.execute("BEGIN EXCLUSIVE TRANSACTION", ())?;
        connection.execute("COMMIT", ())?;

        // Enable fullfsync
        connection.pragma_update(None, "fullfsync", "true")?;

        // Create a table check sql statement
        let mut exists_stmt = connection
            .prepare_cached("SELECT name FROM sqlite_master WHERE type='table' AND name=?")?;

        // Check if the required tables exist and if needed create them
        for idx in desc.db_map_count().indices() {
            let table_name = &desc.db_maps()[idx].name();
            // Check if table is missing
            let is_missing = exists_stmt
                .query_row([&table_name], |row| row.get::<usize, String>(0))
                .optional()?
                .is_none();
            // Create the table if needed
            if is_missing {
                connection.execute(queries::create_table_query(table_name).as_str(), ())?;
            }
        }
        drop(exists_stmt);

        // Set statement cache to fit all the prepared statements we use
        let statement_cap = max(desc.db_map_count().as_usize() * 4, 16);
        connection.set_prepared_statement_cache_capacity(statement_cap);

        Ok(connection)
    }
}

impl backend::Backend for Sqlite {
    type Impl = SqliteImpl;

    fn open(self, desc: DbDesc) -> storage_core::Result<Self::Impl> {
        // Attempt to create the parent storage directory if using a file

        if let SqliteStorageMode::File(ref path) = self.backend {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(error::process_io_error)?;
            } else {
                return Err(storage_core::error::Fatal::Io(
                    std::io::ErrorKind::NotFound,
                    "Cannot find the parent directory".to_string(),
                )
                .into());
            }
        }

        let queries = desc.db_maps().transform(queries::SqliteQuery::from_desc);

        let connection = self.open_db(desc).map_err(process_sqlite_error)?;

        Ok(SqliteImpl(Arc::new(SqliteConnection {
            connection: Mutex::new(connection),
            queries,
        })))
    }
}

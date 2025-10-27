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

//! A `Backend` implementation for Sqlite whose transactions are `Send`, so it's usable
//! in an async context.

extern crate core;

mod error;
mod queries;

use std::{
    borrow::Cow,
    cmp::max,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use error::process_sqlite_error;
use storage_core::{backend, Data, DbDesc, DbMapId};

use crate::queries::SqliteQueries;

// Note: DbTx holds the mutex itself and locks it on every operation instead of just holding a lock
// all the time. This is because we want it to be Send, and locks are not.
pub struct DbTx<'m, const IS_READONLY: bool> {
    connection: Arc<Mutex<SqliteConnection>>,
    queries: &'m SqliteQueries,
}

impl<'m, const IS_READONLY: bool> DbTx<'m, IS_READONLY> {
    fn start_transaction(sqlite: &'m SqliteImpl) -> storage_core::Result<Self> {
        let conn_lock = sqlite.connection.lock().expect("poisoned mutex");

        // Note: there shouldn't be any potentially panicking code between the DbTx creation
        // and the increment of read_only_tx_count, otherwise DbTx::drop will make an erroneous
        // decrement and potentially panic itself due to an assertion failure (which is probably
        // not critical if we're already panicking, but still).
        // This is why we create `conn_lock` before creating the `tx`.
        let tx = DbTx {
            connection: Arc::clone(&sqlite.connection),
            queries: &sqlite.queries,
        };
        tx.init(conn_lock)?;

        Ok(tx)
    }

    // Note: the purpose of this function is to ensure that whatever happens the lock
    // will be dropped before the tx itself, because otherwise `drop` may deadlock when
    // it also tries to lock the same mutex.
    fn init(&self, mut conn_lock: MutexGuard<'_, SqliteConnection>) -> storage_core::Result<()> {
        let need_start_actual_tx = if IS_READONLY {
            // Only start the actual transaction once, so that multiple ro transaction objects
            // can co-exist. See the comment near `read_only_tx_count` for details.
            conn_lock.read_only_tx_count += 1;
            conn_lock.read_only_tx_count == 1
        } else {
            // Sanity check
            assert!(conn_lock.read_only_tx_count == 0);

            true
        };

        if need_start_actual_tx {
            let _res = conn_lock
                .connection
                .execute("BEGIN TRANSACTION", ())
                .map_err(process_sqlite_error)?;
        };

        Ok(())
    }

    fn lock_connection(&self) -> MutexGuard<'_, SqliteConnection> {
        self.connection.lock().expect("poisoned mutex")
    }
}

impl<'m> DbTx<'m, false> {
    fn commit_transaction(self) -> storage_core::Result<()> {
        let conn_lock = self.lock_connection();

        // Sanity check
        assert!(conn_lock.read_only_tx_count == 0);

        let _res = conn_lock
            .connection
            .execute("COMMIT TRANSACTION", ())
            .map_err(process_sqlite_error)?;

        Ok(())
    }
}

impl<const IS_READONLY: bool> Drop for DbTx<'_, IS_READONLY> {
    fn drop(&mut self) {
        let mut conn_lock = self.lock_connection();

        // Note: is_autocommit basically checks whether there are no existing transaction
        // (sqlite is in the autocommit mode by default; it switches to the manual mode on
        // BEGIN and returns to autocommit mode after COMMIT or ROLLBACK).
        // We can only get into this 'if' if `drop` is being called as a result of `commit_transaction`.
        if conn_lock.connection.is_autocommit() {
            assert!(!IS_READONLY);
            return;
        }

        let need_actual_rollback = if IS_READONLY {
            assert!(conn_lock.read_only_tx_count > 0);

            conn_lock.read_only_tx_count -= 1;
            conn_lock.read_only_tx_count == 0
        } else {
            // Sanity check
            assert!(conn_lock.read_only_tx_count == 0);

            true
        };

        if need_actual_rollback {
            let res = conn_lock.connection.execute("ROLLBACK TRANSACTION", ());
            if let Err(err) = res {
                logging::log::error!("Error: transaction rollback failed: {}", err);
            }
        }
    }
}

impl<const IS_READONLY: bool> backend::ReadOps for DbTx<'_, IS_READONLY> {
    fn get(&self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<Option<Cow<'_, [u8]>>> {
        let conn_lock = self.lock_connection();

        let mut stmt = conn_lock
            .connection
            .prepare_cached(self.queries[map_id].get_query())
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
    ) -> storage_core::Result<impl Iterator<Item = (Data, Data)> + '_> {
        // TODO check if prefix.is_empty()
        // TODO Perform the filtering in the SQL query itself
        let conn_lock = self.lock_connection();
        let mut stmt = conn_lock
            .connection
            .prepare_cached(self.queries[map_id].prefix_iter_query())
            .map_err(process_sqlite_error)?;

        let mut rows = stmt.query(()).map_err(process_sqlite_error)?;

        // TODO Move the statement/rows inside the iterator (will require a self-referential struct)
        let mut kv = Vec::new();
        while let Some(row) = rows.next().map_err(process_sqlite_error)? {
            let key = row.get::<usize, Vec<u8>>(0).map_err(process_sqlite_error)?;
            if key.starts_with(&prefix) {
                let value = row.get::<usize, Vec<u8>>(1).map_err(process_sqlite_error)?;
                kv.push((key, value));
            }
        }
        Ok(kv.into_iter())
    }

    fn greater_equal_iter(
        &self,
        map_id: DbMapId,
        key: Data,
    ) -> storage_core::Result<impl Iterator<Item = (Data, Data)> + '_> {
        let conn_lock = self.lock_connection();
        let mut stmt = conn_lock
            .connection
            .prepare_cached(&self.queries[map_id].greater_equal_iter_query(&key))
            .map_err(process_sqlite_error)?;

        let mut rows = stmt.query(()).map_err(process_sqlite_error)?;

        // TODO Move the statement/rows inside the iterator (will require a self-referential struct)

        let mut kv = Vec::new();
        while let Some(row) = rows.next().map_err(process_sqlite_error)? {
            let key = row.get::<usize, Vec<u8>>(0).map_err(process_sqlite_error)?;

            let value = row.get::<usize, Vec<u8>>(1).map_err(process_sqlite_error)?;
            kv.push((key, value));
        }
        Ok(kv.into_iter())
    }
}

impl backend::WriteOps for DbTx<'_, false> {
    fn put(&mut self, map_id: DbMapId, key: Data, val: Data) -> storage_core::Result<()> {
        let conn_lock = self.lock_connection();
        let mut stmt = conn_lock
            .connection
            .prepare_cached(self.queries[map_id].put_query())
            .map_err(process_sqlite_error)?;

        let params = (key, val);
        let _res = stmt.execute(params).map_err(process_sqlite_error)?;

        Ok(())
    }

    fn del(&mut self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<()> {
        let conn_lock = self.lock_connection();
        let mut stmt = conn_lock
            .connection
            .prepare_cached(self.queries[map_id].delete_query())
            .map_err(process_sqlite_error)?;

        let params = (key,);
        let _res = stmt.execute(params).map_err(process_sqlite_error)?;

        Ok(())
    }
}

impl<const IS_READONLY: bool> backend::TxRo for DbTx<'_, IS_READONLY> {}

impl backend::TxRw for DbTx<'_, false> {
    fn commit(self) -> storage_core::Result<()> {
        self.commit_transaction()
    }
}

/// Struct that holds the details for an Sqlite connection
struct SqliteConnection {
    /// The underlying `rusqlite::Connection` object.
    ///
    /// Note that this object is not `Sync`, therefore if we want our `DbTx` to be `Send`, we can't
    /// just put a reference to `Connection` inside it. This is why it's also under the mutex.
    connection: Connection,

    /// The number of readonly `DbTx` instances that currently exist for this connection.
    ///
    /// Note: this is needed because sqlite doesn't allow nested transactions, but we still want
    /// for multiple ro transaction objects to co-exist (because nothing prevents the user code
    /// from calling SqliteImpl::transaction_ro multiple times). So every time an ro DbTx is
    /// created, we'll increment this counter and we'll create a real transaction only if it's
    /// the first increment.
    read_only_tx_count: usize,
}

impl SqliteConnection {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            read_only_tx_count: 0,
        }
    }
}

// Note: this struct is deliberately non-clonable even though it's technically trivial to clone
// (especially if `SqliteQueries` was put inside `SqliteConnection`); as a result, `Sqlite`
// doesn't implement `SharedBackend`.
// The reason is that if it were clonable, we would have to protect against having multiple rw
// transactions at the same time; the only way to do this is to keep the `Mutex<SqliteConnection>`
// locked for the entire lifetime of the transaction (which was done in the original implementation
// of this backend). But this would make `DbTx` non-`Send` (and also dangerous to use, because
// creating two rw transactions on the same thread would lead to a deadlock).
pub struct SqliteImpl {
    /// The current connection.
    connection: Arc<Mutex<SqliteConnection>>,

    /// List of sql queries.
    queries: SqliteQueries,
}

impl backend::BackendImpl for SqliteImpl {
    type TxRo<'a> = DbTx<'a, true>;

    type TxRw<'a> = DbTx<'a, false>;

    fn transaction_ro(&self) -> storage_core::Result<Self::TxRo<'_>> {
        DbTx::start_transaction(self)
    }

    fn transaction_rw(&mut self, _size: Option<usize>) -> storage_core::Result<Self::TxRw<'_>> {
        DbTx::start_transaction(self)
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Options {
    /// If enabled, sets synchronous pragma to OFF, see <https://www.sqlite.org/pragma.html#pragma_synchronous>.
    /// It should normally only be used in unit tests.
    pub disable_fsync: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for Options {
    fn default() -> Self {
        Self {
            disable_fsync: false,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
enum SqliteStorageMode {
    InMemory(Option<String>),
    File(PathBuf),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Sqlite {
    backend: SqliteStorageMode,
    options: Options,
}

impl Sqlite {
    /// Create a distinct "unnamed" in-memory database.
    ///
    /// Only one connection to the database may exist.
    /// Different calls to `Sqlite::new_in_memory().open(...)` will always create different databases.
    pub fn new_in_memory() -> Self {
        Self {
            backend: SqliteStorageMode::InMemory(None),
            options: Default::default(),
        }
    }

    /// Create/open a "named" in-memory database (the one using "shared cache" in the Sqlite's
    /// terminology).
    ///
    /// Different calls to `Sqlite::new_named_in_memory("foo").open(...)` will open the same
    /// database, provided that at least one connection to it still exists.
    /// After all connections to the database are dropped, it is deleted.
    pub fn new_named_in_memory(name: &str) -> Self {
        Self {
            backend: SqliteStorageMode::InMemory(Some(name.to_owned())),
            options: Default::default(),
        }
    }

    /// New Sqlite database backend
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            backend: SqliteStorageMode::File(path.as_ref().to_path_buf()),
            options: Default::default(),
        }
    }

    pub fn with_options(self, options: Options) -> Self {
        Self {
            backend: self.backend,
            options,
        }
    }

    fn open_db(self, desc: DbDesc) -> rusqlite::Result<Connection> {
        let flags = OpenFlags::from_iter([
            OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            OpenFlags::SQLITE_OPEN_CREATE,
        ]);

        let path = match self.backend {
            SqliteStorageMode::File(path) => path,
            SqliteStorageMode::InMemory(None) => ":memory:".into(),
            SqliteStorageMode::InMemory(Some(name)) => {
                format!("file:{name}?mode=memory&cache=shared").into()
            }
        };

        let connection = Connection::open_with_flags(path, flags)?;

        let Options { disable_fsync } = self.options;

        // Set the locking mode to exclusive
        connection.pragma_update(None, "locking_mode", "exclusive")?;

        if disable_fsync {
            connection.pragma_update(None, "synchronous", "OFF")?;
        } else {
            // Enable fullfsync (only affects macOS)
            connection.pragma_update(None, "fullfsync", "true")?;
        }

        // Begin a transaction to acquire the exclusive lock
        connection.execute("BEGIN EXCLUSIVE TRANSACTION", ())?;
        connection.execute("COMMIT", ())?;

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

        Ok(SqliteImpl {
            connection: Arc::new(Mutex::new(SqliteConnection::new(connection))),
            queries,
        })
    }
}

impl backend::BackendWithSendableTransactions for Sqlite {
    type ImplHelper = SqliteImpl;
}

// Note: since these tests are compile time only, there is no need to hide the module
// under `cfg(test)`.
mod compile_time_tests {
    use super::*;

    static_assertions::assert_not_impl_any!(SqliteImpl: Clone, Copy);

    static_assertions::assert_impl_all!(DbTx<'static, true>: Send);
    static_assertions::assert_impl_all!(DbTx<'static, false>: Send);
}

#[cfg(test)]
mod tests;

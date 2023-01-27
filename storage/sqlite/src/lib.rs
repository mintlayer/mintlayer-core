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

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::vec::IntoIter;

use crate::error::process_sqlite_error;
use storage_core::{
    backend::{self, TransactionalRo, TransactionalRw},
    info::DbDesc,
    Data, DbIndex,
};
use utils::shallow_clone::ShallowClone;
use utils::sync::Arc;

/// The version of the SQLite key/value schema
const SQLITE_SCHEMA_VERSION: i32 = 0;

/// Identifiers of the list of databases (key-value maps)
#[derive(Eq, PartialEq, Debug, Clone)]
struct DbList(Vec<()>);

impl std::ops::Index<DbIndex> for DbList {
    type Output = ();

    fn index(&self, index: DbIndex) -> &Self::Output {
        &self.0[index.get()]
    }
}

/// Sqlite iterator over entries with given key prefix
pub struct PrefixIter {
    /// Underlying iterator
    iter: IntoIter<(Vec<u8>, Vec<u8>)>,

    /// Prefix to iterate over
    prefix: Data,
}

impl PrefixIter {
    fn new(iter: IntoIter<(Vec<u8>, Vec<u8>)>, prefix: Data) -> Self {
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
}

impl<'m> DbTx<'m> {
    pub fn start_transaction(connection: MutexGuard<'m, Connection>) -> storage_core::Result<Self> {
        let tx = DbTx { connection };
        tx.connection.execute("BEGIN TRANSACTION", ()).map_err(process_sqlite_error)?;
        Ok(tx)
    }

    pub fn commit_transaction(&self) -> storage_core::Result<()> {
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
            println!("Error: transaction rollback failed: {}", err.to_string());
        }
    }
}

impl<'s, 'i> backend::PrefixIter<'i> for DbTx<'s> {
    type Iterator = PrefixIter;

    fn prefix_iter<'t: 'i>(
        &'t self,
        _idx: DbIndex,
        prefix: Data,
    ) -> storage_core::Result<Self::Iterator> {
        // TODO check if prefix.is_empty()
        // TODO Perform the filtering in the SQL query itself
        let mut stmt = self
            .connection
            .prepare_cached("SELECT key, value FROM main ORDER BY key")
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

impl backend::ReadOps for DbTx<'_> {
    fn get(&self, _idx: DbIndex, key: &[u8]) -> storage_core::Result<Option<Cow<[u8]>>> {
        let mut stmt = self
            .connection
            .prepare_cached("SELECT value FROM main WHERE key = ?")
            .map_err(process_sqlite_error)?;

        let key = [key];
        let res = stmt
            .query_row(key, |row| row.get::<usize, Vec<u8>>(0))
            .optional()
            .map_err(process_sqlite_error)?;
        let res = res.map(|v| v.into());
        Ok(res)
    }
}

impl backend::WriteOps for DbTx<'_> {
    fn put(&mut self, _idx: DbIndex, key: Data, val: Data) -> storage_core::Result<()> {
        let mut stmt = self
            .connection
            .prepare_cached("INSERT or REPLACE into main values(?, ?)")
            .map_err(process_sqlite_error)?;

        let kv = [key, val];
        let _res = stmt.execute(kv).map_err(process_sqlite_error)?;

        Ok(())
    }

    fn del(&mut self, _idx: DbIndex, key: &[u8]) -> storage_core::Result<()> {
        let mut stmt = self
            .connection
            .prepare_cached("DELETE FROM main WHERE key = ?")
            .map_err(process_sqlite_error)?;

        let _res = stmt.execute([key]).map_err(process_sqlite_error)?;

        Ok(())
    }
}

impl backend::TxRo for DbTx<'_> {}

impl backend::TxRw for DbTx<'_> {
    fn commit(self) -> storage_core::Result<()> {
        self.commit_transaction()
    }
}

#[derive(Clone)]
pub struct SqliteImpl {
    /// Handle to an Sqlite database connection
    connection: Arc<Mutex<Connection>>,
}

impl SqliteImpl {
    /// Start a transaction using the low-level method provided
    fn start_transaction<'a>(&'a self) -> storage_core::Result<DbTx<'a>> {
        let connection: MutexGuard<Connection> = self
            .connection
            .lock()
            .map_err(|_| storage_core::error::Recoverable::TemporarilyUnavailable)?;
        DbTx::start_transaction(connection)
    }
}

impl<'tx> TransactionalRo<'tx> for SqliteImpl {
    type TxRo = DbTx<'tx>;

    fn transaction_ro<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRo> {
        self.start_transaction()
    }
}

impl<'tx> TransactionalRw<'tx> for SqliteImpl {
    type TxRw = DbTx<'tx>;

    fn transaction_rw<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRw> {
        self.start_transaction()
    }
}

impl ShallowClone for SqliteImpl {}

impl backend::BackendImpl for SqliteImpl {}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Sqlite {
    path: PathBuf,
}

impl Sqlite {
    /// New Sqlite database backend
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    // fn open_db(self, desc: &MapDesc) -> storage_core::Result<Connection> {
    fn open_db(self) -> rusqlite::Result<Connection> {
        let flags = OpenFlags::from_iter([
            OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            OpenFlags::SQLITE_OPEN_CREATE,
        ]);

        let connection = Connection::open_with_flags(self.path, flags)?;

        // Set the locking mode to exclusive
        connection.pragma_update(None, "locking_mode", "exclusive")?;

        // Begin a transaction to acquire the exclusive lock
        connection.execute("BEGIN EXCLUSIVE TRANSACTION", ())?;
        connection.execute("COMMIT", ())?;

        // Enable fullfsync
        connection.pragma_update(None, "fullfsync", "true")?;

        // Check if key/value table exists
        let table_exists = {
            let mut stmt = connection.prepare_cached(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='main'",
            )?;
            stmt.query_row([], |row| row.get::<usize, String>(0)).optional()?.is_some()
        };

        // Create the key/value table and set some metadata if needed
        if !table_exists {
            connection.execute(
                "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)",
                (),
            )?;

            // TODO set the application id

            // Set the schema version
            connection.pragma_update(
                None,
                "schema_version",
                format!("{}", SQLITE_SCHEMA_VERSION),
            )?;
        }

        Ok(connection)
    }
}

impl backend::Backend for Sqlite {
    type Impl = SqliteImpl;

    fn open(self, _desc: DbDesc) -> storage_core::Result<Self::Impl> {
        // Attempt to create the parent storage directory
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(error::process_io_error)?;
        } else {
            return Err(storage_core::error::Recoverable::Io(
                std::io::ErrorKind::NotFound,
                "Cannot find the parent directory".to_string(),
            )
            .into());
        }

        let connection = self.open_db().map_err(process_sqlite_error)?;

        Ok(SqliteImpl {
            connection: Arc::new(Mutex::new(connection)),
        })
    }
}

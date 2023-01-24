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

mod error;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction};
use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use crate::error::process_sqlite_error;
use storage_core::{
    backend::{self, TransactionalRo, TransactionalRw},
    info::DbDesc,
    Data, DbIndex,
};
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

/// LMDB iterator over entries with given key prefix
pub struct PrefixIter<'tx, C> {
    /// Underlying iterator
    iter: C,

    /// Prefix to iterate over
    prefix: Data,

    // TODO remove
    _phantom: PhantomData<&'tx ()>,
}

impl<'tx, C> PrefixIter<'tx, C> {
    fn new(iter: C, prefix: Data) -> Self {
        PrefixIter {
            iter,
            prefix,
            _phantom: PhantomData,
        }
    }
}

impl<'tx, C> Iterator for PrefixIter<'tx, C> {
    type Item = (Data, Data);

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
        // let (k, v) = self.iter.next()?.expect("iteration to proceed");
        // utils::ensure!(k.starts_with(&self.prefix));
        // Some((k.to_vec(), v.to_vec()))
    }
}

#[ouroboros::self_referencing]
pub struct DbTx<'m> {
    connection: MutexGuard<'m, Connection>,
    #[borrows(mut connection)]
    #[covariant]
    tx: Transaction<'this>,
    // dbs: &'m DbList,
    // _map_token: RwLockReadGuard<'m, remap::MemMapController>,
}

// type DbTxRo<'a> = DbTx<'a, Transaction<'a>>;
// type DbTxRw<'a> = DbTx<'a, Transaction<'a>>;

impl<'s, 'i> backend::PrefixIter<'i> for DbTx<'s> {
    type Iterator = PrefixIter<'i, ()>;

    fn prefix_iter<'t: 'i>(
        &'t self,
        idx: DbIndex,
        prefix: Data,
    ) -> storage_core::Result<Self::Iterator> {
        todo!()
        // let cursor = self.tx.open_ro_cursor(self.dbs[idx]).or_else(error::process_with_err)?;
        // let iter = if prefix.is_empty() {
        //     cursor.into_iter_start()
        // } else {
        //     cursor.into_iter_from(prefix.as_slice())
        // };
        // Ok(PrefixIter::new(iter, prefix))
    }
}

impl backend::ReadOps for DbTx<'_> {
    fn get(&self, idx: DbIndex, key: &[u8]) -> storage_core::Result<Option<&[u8]>> {
        todo!()
        // self.tx
        //     .get(self.dbs[idx], &key)
        //     .map_or_else(error::process_with_none, |x| Ok(Some(x)))
    }
}

/*
void SQLiteBatch::SetupSQLStatements()
{
    const std::vector<std::pair<sqlite3_stmt**, const char*>> statements{
        {&m_read_stmt, "SELECT value FROM main WHERE key = ?"},
        {&m_insert_stmt, "INSERT INTO main VALUES(?, ?)"},
        {&m_overwrite_stmt, "INSERT or REPLACE into main values(?, ?)"},
        {&m_delete_stmt, "DELETE FROM main WHERE key = ?"},
        {&m_cursor_stmt, "SELECT key, value FROM main"},
    };

    for (const auto& [stmt_prepared, stmt_text] : statements) {
        if (*stmt_prepared == nullptr) {
            int res = sqlite3_prepare_v2(m_database.m_db, stmt_text, -1, stmt_prepared, nullptr);
            if (res != SQLITE_OK) {
                throw std::runtime_error(strprintf(
                    "SQLiteDatabase: Failed to setup SQL statements: %s\n", sqlite3_errstr(res)));
            }
        }
    }
}
 */

impl backend::WriteOps for DbTx<'_> {
    fn put(&mut self, idx: DbIndex, key: Data, val: Data) -> storage_core::Result<()> {
        println!("Put idx = {:?}, (k,v) = {:?}, {:?}", idx, key, val);

        let mut stmt = self
            .borrow_tx()
            .prepare_cached("INSERT or REPLACE into main values(?, ?)")
            .map_err(process_sqlite_error)?;

        let kv = [key, val];
        let res = stmt.execute(kv).map_err(process_sqlite_error)?;

        println!("put result = {}", res);

        Ok(())
    }

    fn del(&mut self, idx: DbIndex, key: &[u8]) -> storage_core::Result<()> {
        println!("del idx = {:?}, k = {:?}", idx, key);

        let mut stmt = self
            .borrow_tx()
            .prepare_cached("DELETE FROM main WHERE key = ?")
            .map_err(process_sqlite_error)?;

        let res = stmt.execute([key]).map_err(process_sqlite_error)?;

        println!("del result = {}", res);

        Ok(())
    }
}

impl backend::TxRo for DbTx<'_> {}

impl backend::TxRw for DbTx<'_> {
    fn commit(self) -> storage_core::Result<()> {
        // todo!()
        self.borrow_tx().commit().map_err(process_sqlite_error)
        // lmdb::Transaction::commit(self.tx).or_else(error::process_with_unit)
    }
}

#[derive(Clone)]
pub struct SqliteImpl {
    /// Handle to an Sqlite database connection
    connection: Arc<Mutex<Connection>>,
    // /// List of open databases
    // dbs: DbList,
    // _phantom: PhantomData<&'conn ()>,
}

impl SqliteImpl {
    /// Start a transaction using the low-level method provided
    fn start_transaction<'a>(
        &'a self,
        // start_tx: impl FnOnce(&'a ()) -> Result<Transaction<'a>, rusqlite::Error>,
    ) -> storage_core::Result<DbTx<'a>> {
        // todo!()

        // TODO implement properly
        let connection: MutexGuard<Connection> = self
            .connection
            .lock()
            .map_err(|_| storage_core::error::Recoverable::TemporarilyUnavailable)?;
        DbTx::try_new(connection, |conn| {
            conn.transaction().map_err(error::process_sqlite_error)
        })
        //let mut tx: Transaction = connection.transaction().map_err(error::process_sqlite_error)?;
        //Ok(DbTx { connection, tx })

        // // Make sure map token is acquired before starting the transaction below
        // let _map_token = self.map_token.read().expect("mutex to be alive");
        // Ok(DbTx {
        //     tx: start_tx(&self.env).or_else(error::process_with_err)?,
        //     dbs: &self.dbs,
        //     _map_token,
        // })
    }
}

// impl<'tx> TransactionalRo<'tx> for SqliteImpl {
//     type TxRo = DbTx<'tx>;
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

        println!("db path = {:?}", self.path);

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

    fn open(self, desc: DbDesc) -> storage_core::Result<Self::Impl> {
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

        // // Set up LMDB environment
        // let environment = lmdb::Environment::new()
        //     .set_max_dbs(desc.len() as u32)
        //     .set_flags(self.flags)
        //     .set_map_size(self.map_size.as_bytes())
        //     .open(&self.path)
        //     .or_else(error::process_with_err)?;

        // // Set up all the databases
        // let dbs = desc
        //     .iter()
        //     .map(|desc| Self::open_db(&environment, desc))
        //     .collect::<storage_core::Result<Vec<_>>>()
        //     .map(DbList)?;

        let connection = self.open_db().map_err(process_sqlite_error)?;

        Ok(SqliteImpl {
            connection: Arc::new(Mutex::new(connection)),
            // dbs,
            // map_token: Arc::new(RwLock::new(remap::MemMapController::new())),
            // tx_size: self.tx_size,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::Sqlite;
    use storage_backend_test_suite::prelude::IDX;
    use storage_core::backend::{ReadOps, TransactionalRo, TransactionalRw, TxRw, WriteOps};
    use storage_core::info::MapDesc;
    use storage_core::{Backend, DbDesc};

    /// Sample database description with `n` maps
    pub fn desc(n: usize) -> DbDesc {
        (0..n).map(|x| MapDesc::new(format!("map_{:02}", x))).collect()
    }

    #[test]
    fn put_and_commit() {
        let test_root = test_utils::test_root!("backend-tests").unwrap();
        let test_dir = test_root.fresh_test_dir("unknown");
        let mut db_file = test_dir.as_ref().to_path_buf();
        db_file.set_file_name("database.sqlite");

        // let sqlite = Sqlite::new(test_dir.as_ref().to_path_buf().with_file_name("database.sqlite"));
        let sqlite = Sqlite::new(db_file);

        let store = sqlite.open(desc(1)).expect("db open to succeed");

        // Create a transaction, modify storage and abort transaction
        let mut dbtx = store.transaction_rw().unwrap();
        dbtx.put(IDX.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
        dbtx.commit().expect("commit to succeed");

        // Check the modification did not happen
        let dbtx = store.transaction_ro().unwrap();
        assert_eq!(dbtx.get(IDX.0, b"hello"), Ok(Some(b"world".as_ref())));
        drop(dbtx);
    }
}

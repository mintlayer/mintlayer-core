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

use rusqlite::{Connection, OpenFlags, Transaction};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Mutex;

use storage_core::error::Fatal;
use storage_core::{
    backend::{self, TransactionalRo, TransactionalRw},
    info::{DbDesc, MapDesc},
    Data, DbIndex,
};
use utils::sync::{Arc, RwLock, RwLockReadGuard};

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

pub struct DbTx<'m, 'conn> {
    tx: Transaction<'conn>,
    dbs: &'m DbList,
    // _map_token: RwLockReadGuard<'m, remap::MemMapController>,
}

// type DbTxRo<'a> = DbTx<'a, Transaction<'a>>;
// type DbTxRw<'a> = DbTx<'a, Transaction<'a>>;

impl<'s, 'i, 'conn> backend::PrefixIter<'i> for DbTx<'s, 'conn> {
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

impl backend::ReadOps for DbTx<'_, '_> {
    fn get(&self, idx: DbIndex, key: &[u8]) -> storage_core::Result<Option<&[u8]>> {
        todo!()
        // self.tx
        //     .get(self.dbs[idx], &key)
        //     .map_or_else(error::process_with_none, |x| Ok(Some(x)))
    }
}

impl backend::WriteOps for DbTx<'_, '_> {
    fn put(&mut self, idx: DbIndex, key: Data, val: Data) -> storage_core::Result<()> {
        todo!()
        // self.tx
        //     .put(self.dbs[idx], &key, &val, lmdb::WriteFlags::empty())
        //     .or_else(error::process_with_unit)
    }

    fn del(&mut self, idx: DbIndex, key: &[u8]) -> storage_core::Result<()> {
        todo!()
        // self.tx.del(self.dbs[idx], &key, None).or_else(error::process_with_unit)
    }
}

impl backend::TxRo for DbTx<'_, '_> {}

impl backend::TxRw for DbTx<'_, '_> {
    fn commit(self) -> storage_core::Result<()> {
        todo!()
        // lmdb::Transaction::commit(self.tx).or_else(error::process_with_unit)
    }
}

#[derive(Clone)]
pub struct SqliteImpl<'conn> {
    /// Handle to an Sqlite database connection
    connection: Arc<Mutex<Connection>>,
    // /// List of open databases
    // dbs: DbList,
    _phantom: PhantomData<&'conn ()>,
}

impl<'conn> SqliteImpl<'conn> {
    /// Start a transaction using the low-level method provided
    fn start_transaction<'a>(
        &'a self,
        start_tx: impl FnOnce(&'a ()) -> Result<Transaction<'conn>, rusqlite::Error>,
    ) -> storage_core::Result<DbTx<'a, 'conn>> {
        todo!()
        // // Make sure map token is acquired before starting the transaction below
        // let _map_token = self.map_token.read().expect("mutex to be alive");
        // Ok(DbTx {
        //     tx: start_tx(&self.env).or_else(error::process_with_err)?,
        //     dbs: &self.dbs,
        //     _map_token,
        // })
    }
}

// impl<'tx, 'conn> TransactionalRo<'tx> for SqliteImpl<'conn> {
//     type TxRo = DbTx<'tx, 'conn>;
impl<'tx, 'conn> TransactionalRo<'tx> for SqliteImpl<'conn> {
    type TxRo = DbTx<'tx, 'conn>;

    fn transaction_ro<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRo> {
        todo!()
        // self.start_transaction(lmdb::Environment::begin_ro_txn)
    }
}

impl<'tx, 'conn> TransactionalRw<'tx> for SqliteImpl<'conn> {
    type TxRw = DbTx<'tx, 'conn>;

    fn transaction_rw<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRw> {
        todo!()
        // self.start_transaction(lmdb::Environment::begin_rw_txn)
    }
}

impl<'conn: 'static> backend::BackendImpl for SqliteImpl<'conn> {}
// impl backend::BackendImpl for SqliteImpl<'_> {}

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
    fn open_db(self) -> storage_core::Result<Connection> {
        let flags = OpenFlags::from_iter([
            OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            OpenFlags::SQLITE_OPEN_CREATE,
        ]);

        // // TODO change error
        let connection = Connection::open_with_flags(self.path, flags)
            .map_err(|err| Fatal::InternalError(err.to_string()))?;
        Ok(connection)

        // let flags = lmdb::DatabaseFlags::default();
        // env.create_db(name, flags).or_else(error::process_with_err)
    }
}

impl backend::Backend for Sqlite {
    type Impl<'conn> = SqliteImpl<'conn>;

    fn open(self, desc: DbDesc) -> storage_core::Result<Self::Impl> {
        // Attempt to create the storage directory
        std::fs::create_dir_all(&self.path).map_err(error::process_io_error)?;

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

        let connection = self.open_db()?;

        Ok(SqliteImpl {
            connection: Arc::new(Mutex::new(connection)),
            // dbs,
            // map_token: Arc::new(RwLock::new(remap::MemMapController::new())),
            // tx_size: self.tx_size,
            _phantom: Default::default(),
        })
    }
}

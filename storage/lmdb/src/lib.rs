// Copyright (c) 2022 RBB S.r.l
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
pub mod initial_map_size;
pub mod memsize;

use std::sync::atomic::{AtomicBool, Ordering};
use std::{borrow::Cow, path::PathBuf};

use initial_map_size::InitialMapSize;
use lmdb::Cursor;
use storage_core::{
    backend::{self, TransactionalRo, TransactionalRw},
    info::{DbDesc, MapDesc},
    Data, DbIndex,
};
use utils::sync::Arc;

pub use lmdb::{DatabaseResizeInfo, DatabaseResizeSettings};

/// Identifiers of the list of databases (key-value maps)
#[derive(Eq, PartialEq, Debug, Clone)]
struct DbList(Vec<lmdb::Database>);

impl std::ops::Index<DbIndex> for DbList {
    type Output = lmdb::Database;

    fn index(&self, index: DbIndex) -> &Self::Output {
        &self.0[index.get()]
    }
}

/// LMDB iterator over entries with given key prefix
pub struct PrefixIter<'tx, C> {
    /// Underlying iterator
    iter: lmdb::Iter<'tx, C>,

    /// Prefix to iterate over
    prefix: Data,
}

impl<'tx, C> PrefixIter<'tx, C> {
    fn new(iter: lmdb::Iter<'tx, C>, prefix: Data) -> Self {
        PrefixIter { iter, prefix }
    }
}

impl<'tx, C: lmdb::Cursor<'tx>> Iterator for PrefixIter<'tx, C> {
    type Item = (Data, Data);

    fn next(&mut self) -> Option<Self::Item> {
        let (k, v) = self.iter.next()?.expect("iteration to proceed");
        utils::ensure!(k.starts_with(&self.prefix));
        Some((k.to_vec(), v.to_vec()))
    }
}

pub struct DbTx<'m, Tx> {
    tx: Tx,
    backend: &'m LmdbImpl,
}

type DbTxRo<'a> = DbTx<'a, lmdb::RoTransaction<'a>>;
type DbTxRw<'a> = DbTx<'a, lmdb::RwTransaction<'a>>;

impl<'s, 'i, Tx: lmdb::Transaction> backend::PrefixIter<'i> for DbTx<'s, Tx> {
    type Iterator = PrefixIter<'i, lmdb::RoCursor<'i>>;

    fn prefix_iter<'t: 'i>(
        &'t self,
        idx: DbIndex,
        prefix: Data,
    ) -> storage_core::Result<Self::Iterator> {
        let cursor =
            self.tx.open_ro_cursor(self.backend.dbs[idx]).or_else(error::process_with_err)?;
        let iter = if prefix.is_empty() {
            cursor.into_iter_start()
        } else {
            cursor.into_iter_from(prefix.as_slice())
        };
        Ok(PrefixIter::new(iter, prefix))
    }
}

impl<Tx: lmdb::Transaction> backend::ReadOps for DbTx<'_, Tx> {
    fn get(&self, idx: DbIndex, key: &[u8]) -> storage_core::Result<Option<Cow<[u8]>>> {
        self.tx
            .get(self.backend.dbs[idx], &key)
            .map_or_else(error::process_with_none, |x| Ok(Some(x.into())))
    }
}

impl backend::WriteOps for DbTx<'_, lmdb::RwTransaction<'_>> {
    fn put(&mut self, idx: DbIndex, key: Data, val: Data) -> storage_core::Result<()> {
        self.tx
            .put(self.backend.dbs[idx], &key, &val, lmdb::WriteFlags::empty())
            .map_err(|err| self.backend.schedule_map_resize_if_map_full(err))
            .or_else(error::process_with_unit)
    }

    fn del(&mut self, idx: DbIndex, key: &[u8]) -> storage_core::Result<()> {
        self.tx
            .del(self.backend.dbs[idx], &key, None)
            .map_err(|err| self.backend.schedule_map_resize_if_map_full(err))
            .or_else(error::process_with_unit)
    }
}

impl backend::TxRo for DbTxRo<'_> {}

impl backend::TxRw for DbTxRw<'_> {
    fn commit(self) -> storage_core::Result<()> {
        lmdb::Transaction::commit(self.tx)
            .map_err(|e| self.backend.resize_if_map_full(e))
            .or_else(error::process_with_unit)
    }
}

#[derive(Clone)]
pub struct LmdbImpl {
    /// Handle to the environment
    env: Arc<lmdb::Environment>,

    /// List of open databases
    dbs: DbList,

    /// Schedule a database resize of the database map
    map_resize_scheduled: Arc<AtomicBool>,
}

impl LmdbImpl {
    /// Start a transaction using the low-level method provided
    fn start_transaction<'a, Tx: 'a>(
        &'a self,
        start_tx: impl FnOnce(&'a lmdb::Environment) -> Result<Tx, lmdb::Error>,
    ) -> storage_core::Result<DbTx<'a, Tx>> {
        // Make sure map token is acquired before starting the transaction below
        Ok(DbTx {
            tx: start_tx(&self.env).or_else(error::process_with_err)?,
            backend: self,
        })
    }

    fn schedule_map_resize(&self) {
        self.map_resize_scheduled.store(true, Ordering::SeqCst);
    }

    fn unschedule_map_resize(&self) {
        self.map_resize_scheduled.store(false, Ordering::SeqCst);
    }

    fn resize_if_resize_scheduled(&self) {
        // simulate an atomic test_and_set(), where we check if a resize is scheduled, and we also set it to false
        if self
            .map_resize_scheduled
            .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
            .unwrap_or(false)
        {
            self.env.do_resize(None).expect("Failed to resize after a trigger to resize");
        }
    }

    /// If the lmdb map is full, perform a resize. This results in fixing
    /// a recoverable error of MDB_MAP_FULL to work out-of-the-box by just
    /// retrying one or more times
    fn resize_if_map_full(&self, err: lmdb::Error) -> lmdb::Error {
        if err == lmdb::Error::MapFull {
            self.env
                .do_resize(None)
                .expect("Failed to resize after a write/commit failed with MDB_MAP_FULL");
            self.unschedule_map_resize();
        }
        err
    }

    fn schedule_map_resize_if_map_full(&self, err: lmdb::Error) -> lmdb::Error {
        if err == lmdb::Error::MapFull {
            self.schedule_map_resize();
        }
        err
    }
}

impl<'tx> TransactionalRo<'tx> for LmdbImpl {
    type TxRo = DbTxRo<'tx>;

    fn transaction_ro<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRo> {
        self.start_transaction(lmdb::Environment::begin_ro_txn)
    }
}

impl<'tx> TransactionalRw<'tx> for LmdbImpl {
    type TxRw = DbTxRw<'tx>;

    fn transaction_rw<'st: 'tx>(
        &'st self,
        size: Option<usize>,
    ) -> storage_core::Result<Self::TxRw> {
        self.resize_if_resize_scheduled();
        self.start_transaction(|env| lmdb::Environment::begin_rw_txn(env, size))
    }
}

impl utils::shallow_clone::ShallowClone for LmdbImpl {}
impl backend::BackendImpl for LmdbImpl {}

pub struct Lmdb {
    path: PathBuf,
    flags: lmdb::EnvironmentFlags,
    inital_map_size: InitialMapSize,
    resize_settings: DatabaseResizeSettings,
    resize_callback: Option<Box<dyn Fn(DatabaseResizeInfo)>>,
}

impl Lmdb {
    /// New LMDB database backend
    pub fn new(
        path: PathBuf,
        inital_map_size: InitialMapSize,
        resize_settings: DatabaseResizeSettings,
        resize_callback: Option<Box<dyn Fn(DatabaseResizeInfo)>>,
    ) -> Self {
        Self {
            path,
            flags: lmdb::EnvironmentFlags::default(),
            inital_map_size,
            resize_settings,
            resize_callback,
        }
    }

    /// Use a writable memory map.
    ///
    /// This disables some protections in exchange for better performance.
    /// See [lmdb::EnvironmentFlags::WRITE_MAP] for more detail.
    pub fn with_write_map(mut self) -> Self {
        self.flags |= lmdb::EnvironmentFlags::WRITE_MAP;
        self
    }

    fn open_db(env: &lmdb::Environment, desc: &MapDesc) -> storage_core::Result<lmdb::Database> {
        let name = Some(desc.name.as_ref());
        let flags = lmdb::DatabaseFlags::default();
        env.create_db(name, flags).or_else(error::process_with_err)
    }
}

impl backend::Backend for Lmdb {
    type Impl = LmdbImpl;

    fn open(self, desc: DbDesc) -> storage_core::Result<Self::Impl> {
        // Attempt to create the storage directory
        std::fs::create_dir_all(&self.path).map_err(error::process_io_error)?;

        let initial_map_size = self
            .inital_map_size
            .into_memsize()
            .as_bytes()
            .try_into()
            .expect("MemSize to usize conversion failed");

        // Set up LMDB environment
        let environment = lmdb::Environment::new()
            .set_max_dbs(desc.len() as u32)
            .set_flags(self.flags)
            .set_map_size(initial_map_size)
            .set_resize_settings(self.resize_settings)
            .set_resize_callback(self.resize_callback)
            .open(&self.path)
            .or_else(error::process_with_err)?;

        // Set up all the databases
        let dbs = desc
            .iter()
            .map(|desc| Self::open_db(&environment, desc))
            .collect::<storage_core::Result<Vec<_>>>()
            .map(DbList)?;

        Ok(LmdbImpl {
            env: Arc::new(environment),
            dbs,
            map_resize_scheduled: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[cfg(test)]
mod resize_tests;

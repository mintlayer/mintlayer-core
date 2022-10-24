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

use std::path::PathBuf;

use lmdb::Cursor;
use storage_core::{
    backend::{self, TransactionalRo, TransactionalRw},
    info::{DbDesc, MapDesc},
    Data, DbIndex,
};
use utils::sync::Arc;

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
    dbs: &'m DbList,
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
        let cursor = self.tx.open_ro_cursor(self.dbs[idx]).or_else(error::process_with_err)?;
        let iter = if prefix.is_empty() {
            cursor.into_iter_start()
        } else {
            cursor.into_iter_from(prefix.as_slice())
        };
        Ok(PrefixIter::new(iter, prefix))
    }
}

impl<Tx: lmdb::Transaction> backend::ReadOps for DbTx<'_, Tx> {
    fn get(&self, idx: DbIndex, key: &[u8]) -> storage_core::Result<Option<&[u8]>> {
        self.tx
            .get(self.dbs[idx], &key)
            .map_or_else(error::process_with_none, |x| Ok(Some(x)))
    }
}

impl backend::WriteOps for DbTx<'_, lmdb::RwTransaction<'_>> {
    fn put(&mut self, idx: DbIndex, key: Data, val: Data) -> storage_core::Result<()> {
        self.tx
            .put(self.dbs[idx], &key, &val, lmdb::WriteFlags::empty())
            .or_else(error::process_with_unit)
    }

    fn del(&mut self, idx: DbIndex, key: &[u8]) -> storage_core::Result<()> {
        self.tx.del(self.dbs[idx], &key, None).or_else(error::process_with_unit)
    }
}

impl backend::TxRo for DbTxRo<'_> {}

impl backend::TxRw for DbTxRw<'_> {
    fn commit(self) -> storage_core::Result<()> {
        lmdb::Transaction::commit(self.tx).or_else(error::process_with_unit)
    }
}

#[derive(Clone)]
pub struct LmdbImpl {
    env: Arc<lmdb::Environment>,
    dbs: DbList,
}

impl<'tx> TransactionalRo<'tx> for LmdbImpl {
    type TxRo = DbTxRo<'tx>;

    fn transaction_ro<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRo> {
        let tx = self.env.begin_ro_txn().or_else(error::process_with_err)?;
        let dbs = &self.dbs;
        Ok(DbTx { tx, dbs })
    }
}

impl<'tx> TransactionalRw<'tx> for LmdbImpl {
    type TxRw = DbTxRw<'tx>;

    fn transaction_rw<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRw> {
        let tx = self.env.begin_rw_txn().or_else(error::process_with_err)?;
        let dbs = &self.dbs;
        Ok(DbTx { tx, dbs })
    }
}

impl backend::BackendImpl for LmdbImpl {}

pub struct Lmdb {
    path: PathBuf,
    flags: lmdb::EnvironmentFlags,
}

impl Lmdb {
    /// New LMDB database backend
    pub fn new(path: PathBuf) -> Self {
        let flags = lmdb::EnvironmentFlags::default();
        Self { path, flags }
    }

    /// Use a writable memory map.
    ///
    /// This disables some protections in excahnge for better performance.
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

        // Set up LMDB environment
        let mut env = lmdb::Environment::new();
        env.set_max_dbs(desc.len() as u32);
        env.set_flags(self.flags);
        //env.set_map_size(todo!());
        //env.set_max_readers(todo!());
        let env = env.open(&self.path).or_else(error::process_with_err)?;

        // Set up all the databases
        let dbs = desc
            .iter()
            .map(|desc| Self::open_db(&env, desc))
            .collect::<storage_core::Result<Vec<_>>>()
            .map(DbList)?;

        let env = Arc::new(env);
        Ok(LmdbImpl { env, dbs })
    }
}

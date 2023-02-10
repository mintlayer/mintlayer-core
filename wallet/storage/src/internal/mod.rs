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

use std::collections::BTreeMap;

use common::chain::OutPoint;
use utxo::Utxo;

use crate::{
    schema::{self as db, Schema},
    TransactionRw, Transactional, WalletStorage, WalletStorageRead, WalletStorageWrite,
};

mod store_tx;
pub use store_tx::{StoreTxRo, StoreTxRw};

/// Store for wallet data, parametrized over the backend B
pub struct Store<B: storage::Backend>(storage::Storage<B, Schema>);

impl<B: storage::Backend> Store<B> {
    /// Create a new wallet storage
    pub fn new(backend: B) -> crate::Result<Self> {
        let mut storage = Self(storage::Storage::new(backend).map_err(crate::Error::from)?);
        storage.set_storage_version(1)?;
        Ok(storage)
    }

    /// Dump raw database contents
    pub fn dump_raw(&self) -> crate::Result<storage::raw::StorageContents<Schema>> {
        self.0.dump_raw().map_err(crate::Error::from)
    }

    /// Collect and return all utxos from the storage
    #[allow(clippy::let_and_return)]
    pub fn read_utxo_set(&self) -> crate::Result<BTreeMap<OutPoint, Utxo>> {
        let db_tx = self.transaction_ro()?;
        let map = db_tx.0.get::<db::DBUtxo, _>();
        let res = map.prefix_iter_decoded(&())?.collect::<BTreeMap<_, _>>();

        Ok(res)
    }
}

impl<B: storage::Backend> Clone for Store<B>
where
    B::Impl: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'tx, B: storage::Backend + 'tx> Transactional<'tx> for Store<B> {
    type TransactionRo = store_tx::StoreTxRo<'tx, B>;
    type TransactionRw = store_tx::StoreTxRw<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRo> {
        self.0.transaction_ro().map_err(crate::Error::from).map(store_tx::StoreTxRo)
    }

    fn transaction_rw<'st: 'tx>(
        &'st self,
        size: Option<usize>,
    ) -> crate::Result<Self::TransactionRw> {
        self.0.transaction_rw(size).map_err(crate::Error::from).map(StoreTxRw)
    }
}

impl<B: storage::Backend + 'static> WalletStorage for Store<B> {}

macro_rules! delegate_to_transaction {
    ($($(#[size=$s:expr])? fn $func:ident $args:tt -> $ret:ty;)*) => {
        $(delegate_to_transaction!(@FN $(#[size = $s])? $func $args -> $ret);)*
    };
    (@FN $f:ident(&self $(, $arg:ident: $aty:ty)* $(,)?) -> $ret:ty) => {
        fn $f(&self $(, $arg: $aty)*) -> $ret {
            self.transaction_ro().and_then(|tx| tx.$f($($arg),*))
        }
    };
    (@FN $(#[size=$s:expr])? $f:ident(&mut self $(, $arg:ident: $aty:ty)* $(,)?) -> $ret:ty) => {
        fn $f(&mut self $(, $arg: $aty)*) -> $ret {
            let size = delegate_to_transaction!(@SIZE $($s)?);
            let mut tx = self.transaction_rw(size)?;
            let val = tx.$f($($arg),*)?;
            tx.commit()?;
            Ok(val)
        }
    };
    (@SIZE) => { None };
    (@SIZE $s:literal) => { Some($s) };
}

impl<B: storage::Backend> WalletStorageRead for Store<B> {
    delegate_to_transaction! {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
    }
}

impl<B: storage::Backend> WalletStorageWrite for Store<B> {
    delegate_to_transaction! {
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;
    }
}

#[cfg(test)]
mod test;

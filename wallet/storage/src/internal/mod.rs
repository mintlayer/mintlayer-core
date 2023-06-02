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

use common::address::Address;
use crypto::key::extended::ExtendedPublicKey;

use crate::{
    schema::Schema, TransactionRw, Transactional, WalletStorage, WalletStorageRead,
    WalletStorageWrite,
};

mod store_tx;
pub use store_tx::{StoreTxRo, StoreTxRw};
use wallet_types::{
    wallet_tx::WalletTx, AccountDerivationPathId, AccountId, AccountInfo, AccountKeyPurposeId,
    AccountWalletTxId, KeychainUsageState, RootKeyContent, RootKeyId,
};

/// Store for wallet data, parametrized over the backend B
pub struct Store<B: storage::Backend>(storage::Storage<B, Schema>);

impl<B: storage::Backend> Store<B> {
    /// Create a new wallet storage
    pub fn new(backend: B) -> crate::Result<Self> {
        let storage = Self(storage::Storage::new(backend).map_err(crate::Error::from)?);
        Ok(storage)
    }

    /// Dump raw database contents
    pub fn dump_raw(&self) -> crate::Result<storage::raw::StorageContents<Schema>> {
        self.0.dump_raw().map_err(crate::Error::from)
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
    type TransactionRo = StoreTxRo<'tx, B>;
    type TransactionRw = StoreTxRw<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRo> {
        self.0.transaction_ro().map_err(crate::Error::from).map(StoreTxRo)
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
        fn get_transaction(&self, id: &AccountWalletTxId) -> crate::Result<Option<WalletTx>>;
        fn get_transactions(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountWalletTxId, WalletTx>>;
        fn get_accounts_info(&self) -> crate::Result<BTreeMap<AccountId, AccountInfo>>;
        fn get_address(&self, id: &AccountDerivationPathId) -> crate::Result<Option<Address>>;
        fn get_addresses(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountDerivationPathId, Address>>;
        fn get_root_key(&self, id: &RootKeyId) -> crate::Result<Option<RootKeyContent >>;
        fn get_all_root_keys(&self) -> crate::Result<BTreeMap<RootKeyId, RootKeyContent >>;
        fn get_keychain_usage_state(&self, id: &AccountKeyPurposeId) -> crate::Result<Option<KeychainUsageState>>;
        fn get_keychain_usage_states(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountKeyPurposeId, KeychainUsageState>>;
        fn get_public_key(&self, id: &AccountDerivationPathId) -> crate::Result<Option<ExtendedPublicKey>>;
        fn get_public_keys(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountDerivationPathId, ExtendedPublicKey>>;
    }
}

impl<B: storage::Backend> WalletStorageWrite for Store<B> {
    delegate_to_transaction! {
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn set_transaction(&mut self, id: &AccountWalletTxId, tx: &WalletTx) -> crate::Result<()>;
        fn del_transaction(&mut self, id: &AccountWalletTxId) -> crate::Result<()>;
        fn set_account(&mut self, id: &AccountId, content: &AccountInfo) -> crate::Result<()>;
        fn del_account(&mut self, id: &AccountId) -> crate::Result<()>;
        fn set_address(&mut self, id: &AccountDerivationPathId, address: &Address) -> crate::Result<()>;
        fn del_address(&mut self, id: &AccountDerivationPathId) -> crate::Result<()>;
        fn set_root_key(&mut self, id: &RootKeyId, content: &RootKeyContent) -> crate::Result<()>;
        fn del_root_key(&mut self, id: &RootKeyId) -> crate::Result<()>;
        fn set_keychain_usage_state(&mut self, id: &AccountKeyPurposeId, address: &KeychainUsageState) -> crate::Result<()>;
        fn del_keychain_usage_state(&mut self, id: &AccountKeyPurposeId) -> crate::Result<()>;
        fn set_public_key(&mut self, id: &AccountDerivationPathId, content: &ExtendedPublicKey) -> crate::Result<()>;
        fn det_public_key(&mut self, id: &AccountDerivationPathId) -> crate::Result<()>;
    }
}

#[cfg(test)]
mod test;

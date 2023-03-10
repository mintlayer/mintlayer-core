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

//! Application-level interface for the persistent wallet storage.

mod internal;
mod is_transaction_seal;
pub mod schema;

use common::address::Address;
pub use internal::{Store, StoreTxRo, StoreTxRw};
use std::collections::BTreeMap;

use utxo::Utxo;
use wallet_types::{
    AccountAddressId, AccountId, AccountInfo, AccountOutPointId, AccountTxId, KeyContent, KeyId,
    KeyType, WalletTx,
};

/// Possibly failing result of wallet storage query
pub type Result<T> = storage::Result<T>;
pub type Error = storage::Error;

/// Queries on persistent wallet data
pub trait WalletStorageRead {
    /// Get storage version
    fn get_storage_version(&self) -> Result<u32>;
    fn get_utxo(&self, outpoint: &AccountOutPointId) -> Result<Option<Utxo>>;
    fn read_utxo_set(&self, account_id: &AccountId) -> Result<BTreeMap<AccountOutPointId, Utxo>>;
    fn get_transaction(&self, id: &AccountTxId) -> Result<Option<WalletTx>>;
    fn read_transactions(&self, account_id: &AccountId) -> Result<BTreeMap<AccountTxId, WalletTx>>;
    fn get_account(&self, id: &AccountId) -> Result<Option<AccountInfo>>;
    fn get_address(&self, id: &AccountAddressId) -> Result<Option<Address>>;
    fn read_addresses(&self, account_id: &AccountId)
        -> Result<BTreeMap<AccountAddressId, Address>>;
    fn get_key(&self, id: &KeyId) -> Result<Option<KeyContent>>;
    fn get_key_by_type(&self, key_type: &KeyType) -> Result<BTreeMap<KeyId, KeyContent>>;
}

/// Modifying operations on persistent wallet data
pub trait WalletStorageWrite: WalletStorageRead {
    /// Set storage version
    fn set_storage_version(&mut self, version: u32) -> Result<()>;
    fn set_utxo(&mut self, outpoint: &AccountOutPointId, entry: Utxo) -> Result<()>;
    fn del_utxo(&mut self, outpoint: &AccountOutPointId) -> Result<()>;
    fn set_transaction(&mut self, id: &AccountTxId, tx: &WalletTx) -> Result<()>;
    fn del_transaction(&mut self, id: &AccountTxId) -> Result<()>;
    fn set_account(&mut self, id: &AccountId, content: &AccountInfo) -> Result<()>;
    fn del_account(&mut self, id: &AccountId) -> Result<()>;
    fn set_address(&mut self, id: &AccountAddressId, address: &Address) -> Result<()>;
    fn del_address(&mut self, id: &AccountAddressId) -> Result<()>;
    fn set_key(&mut self, id: &KeyId, content: &KeyContent) -> Result<()>;
    fn del_key(&mut self, id: &KeyId) -> Result<()>;
}

/// Marker trait for types where read/write operations are run in a transaction
pub trait IsTransaction: is_transaction_seal::Seal {}

/// Operations on read-only transactions
pub trait TransactionRo: WalletStorageRead + IsTransaction {
    /// Close the transaction
    fn close(self);
}

/// Operations on read-write transactions
pub trait TransactionRw: WalletStorageWrite + IsTransaction {
    /// Abort the transaction
    fn abort(self);

    /// Commit the transaction
    fn commit(self) -> Result<()>;
}

/// Support for transactions over wallet storage
pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: TransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: TransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self, size: Option<usize>) -> Result<Self::TransactionRw>;
}

pub trait WalletStorage: WalletStorageWrite + for<'tx> Transactional<'tx> + Send {}

pub type DefaultBackend = storage_sqlite::Sqlite;
pub type WalletStorageTxRwImpl<'st> = StoreTxRw<'st, storage_sqlite::Sqlite>;

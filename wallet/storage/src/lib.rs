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
use crypto::key::extended::ExtendedPublicKey;
pub use internal::{Store, StoreTxRo, StoreTxRw};
use std::collections::BTreeMap;

use wallet_types::{
    account_id::AccountBlockHeight, wallet_block::WalletBlock, AccountDerivationPathId, AccountId,
    AccountInfo, AccountKeyPurposeId, AccountTxId, KeychainUsageState, RootKeyContent, RootKeyId,
    WalletTx,
};

/// Possibly failing result of wallet storage query
pub type Result<T> = storage::Result<T>;
pub type Error = storage::Error;

/// Queries on persistent wallet data
pub trait WalletStorageRead {
    /// Get storage version
    fn get_storage_version(&self) -> Result<u32>;
    fn get_block(&self, block_height: &AccountBlockHeight) -> Result<Option<WalletBlock>>;
    fn get_blocks(
        &self,
        account_id: &AccountId,
    ) -> Result<BTreeMap<AccountBlockHeight, WalletBlock>>;
    fn get_transaction(&self, id: &AccountTxId) -> Result<Option<WalletTx>>;
    fn get_transactions(&self, account_id: &AccountId) -> Result<BTreeMap<AccountTxId, WalletTx>>;
    fn get_accounts_info(&self) -> crate::Result<BTreeMap<AccountId, AccountInfo>>;
    fn get_address(&self, id: &AccountDerivationPathId) -> Result<Option<Address>>;
    fn get_addresses(
        &self,
        account_id: &AccountId,
    ) -> Result<BTreeMap<AccountDerivationPathId, Address>>;
    fn get_root_key(&self, id: &RootKeyId) -> Result<Option<RootKeyContent>>;
    fn get_all_root_keys(&self) -> Result<BTreeMap<RootKeyId, RootKeyContent>>;
    fn get_keychain_usage_state(
        &self,
        id: &AccountKeyPurposeId,
    ) -> Result<Option<KeychainUsageState>>;
    fn get_keychain_usage_states(
        &self,
        account_id: &AccountId,
    ) -> Result<BTreeMap<AccountKeyPurposeId, KeychainUsageState>>;
    fn get_public_key(&self, id: &AccountDerivationPathId) -> Result<Option<ExtendedPublicKey>>;
    fn get_public_keys(
        &self,
        account_id: &AccountId,
    ) -> Result<BTreeMap<AccountDerivationPathId, ExtendedPublicKey>>;
}

/// Modifying operations on persistent wallet data
pub trait WalletStorageWrite: WalletStorageRead {
    /// Set storage version
    fn set_storage_version(&mut self, version: u32) -> Result<()>;
    fn set_block(
        &mut self,
        block_height: &AccountBlockHeight,
        block: &WalletBlock,
    ) -> crate::Result<()>;
    fn del_block(&mut self, block_height: &AccountBlockHeight) -> crate::Result<()>;
    fn set_transaction(&mut self, id: &AccountTxId, tx: &WalletTx) -> Result<()>;
    fn del_transaction(&mut self, id: &AccountTxId) -> Result<()>;
    fn set_account(&mut self, id: &AccountId, content: &AccountInfo) -> Result<()>;
    fn del_account(&mut self, id: &AccountId) -> Result<()>;
    fn set_address(&mut self, id: &AccountDerivationPathId, address: &Address) -> Result<()>;
    fn del_address(&mut self, id: &AccountDerivationPathId) -> Result<()>;
    fn set_root_key(&mut self, id: &RootKeyId, content: &RootKeyContent) -> Result<()>;
    fn del_root_key(&mut self, id: &RootKeyId) -> Result<()>;
    fn set_keychain_usage_state(
        &mut self,
        id: &AccountKeyPurposeId,
        usage_state: &KeychainUsageState,
    ) -> Result<()>;
    fn del_keychain_usage_state(&mut self, id: &AccountKeyPurposeId) -> Result<()>;
    fn set_public_key(
        &mut self,
        id: &AccountDerivationPathId,
        content: &ExtendedPublicKey,
    ) -> Result<()>;
    fn det_public_key(&mut self, id: &AccountDerivationPathId) -> Result<()>;
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

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

use common::{
    address::{Address, AddressError},
    chain::{block::timestamp::BlockTimestamp, Destination, SignedTransaction},
};
use crypto::{kdf::KdfChallenge, key::extended::ExtendedPublicKey, symkey::SymmetricKey};
pub use internal::{Store, StoreTxRo, StoreTxRoUnlocked, StoreTxRw, StoreTxRwUnlocked};
use std::collections::BTreeMap;

use wallet_types::{
    keys::RootKeys, AccountDerivationPathId, AccountId, AccountInfo, AccountKeyPurposeId,
    AccountWalletCreatedTxId, AccountWalletTxId, KeychainUsageState, WalletTx,
};

/// Wallet Errors
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    StorageError(#[from] storage::Error),
    #[error("The wallet is locked")]
    WalletLocked,
    #[error("Cannot encrypt the wallet with an empty password")]
    WalletEmptyPassword,
    #[error("Invalid wallet password")]
    WalletInvalidPassword,
    #[error("The wallet is already unlocked")]
    WalletAlreadyUnlocked,
    #[error("Cannot lock the wallet without setting a password")]
    WalletLockedWithoutAPassword,
    #[error("Wallet file corrupted root keys expected 1 got {0}")]
    WalletSanityErrorInvalidRootKeyCount(usize),
    #[error("Cannot decode address from DB {0}")]
    CannotDecodeAddress(#[from] AddressError),
}

/// Possibly failing result of wallet storage query
pub type Result<T> = std::result::Result<T, Error>;

/// Queries on persistent wallet data
pub trait WalletStorageReadLocked {
    /// Get storage version
    fn get_storage_version(&self) -> Result<u32>;
    fn get_transaction(&self, id: &AccountWalletTxId) -> Result<Option<WalletTx>>;
    fn get_transactions(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<(AccountWalletTxId, WalletTx)>>;
    fn get_user_transactions(&self) -> Result<Vec<SignedTransaction>>;
    fn get_accounts_info(&self) -> crate::Result<BTreeMap<AccountId, AccountInfo>>;
    fn get_address(&self, id: &AccountDerivationPathId) -> Result<Option<String>>;
    fn get_addresses(
        &self,
        account_id: &AccountId,
    ) -> Result<BTreeMap<AccountDerivationPathId, String>>;
    fn check_root_keys_sanity(&self) -> Result<()>;
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
    fn get_median_time(&self) -> Result<Option<BlockTimestamp>>;
}

/// Queries on persistent wallet data with access to encrypted data
pub trait WalletStorageReadUnlocked: WalletStorageReadLocked {
    fn get_root_key(&self) -> Result<Option<RootKeys>>;
}

/// Queries on persistent wallet data for encryption
pub trait WalletStorageEncryptionRead {
    fn get_encryption_key_kdf_challenge(&self) -> Result<Option<KdfChallenge>>;
    fn check_can_decrypt_all_root_keys(&self, encryption_key: &SymmetricKey) -> crate::Result<()>;
}

/// Modifying operations on persistent wallet data
pub trait WalletStorageWriteLocked: WalletStorageReadLocked {
    /// Set storage version
    fn set_storage_version(&mut self, version: u32) -> Result<()>;
    fn set_transaction(&mut self, id: &AccountWalletTxId, tx: &WalletTx) -> Result<()>;
    fn del_transaction(&mut self, id: &AccountWalletTxId) -> Result<()>;
    fn set_user_transaction(
        &mut self,
        id: &AccountWalletCreatedTxId,
        tx: &SignedTransaction,
    ) -> Result<()>;
    fn del_user_transaction(&mut self, id: &AccountWalletCreatedTxId) -> crate::Result<()>;
    fn set_account(&mut self, id: &AccountId, content: &AccountInfo) -> Result<()>;
    fn del_account(&mut self, id: &AccountId) -> Result<()>;
    fn set_address(
        &mut self,
        id: &AccountDerivationPathId,
        address: &Address<Destination>,
    ) -> Result<()>;
    fn del_address(&mut self, id: &AccountDerivationPathId) -> Result<()>;
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
    fn set_median_time(&mut self, median_time: BlockTimestamp) -> Result<()>;
}

/// Modifying operations on persistent wallet data with access to encrypted data
pub trait WalletStorageWriteUnlocked: WalletStorageReadUnlocked + WalletStorageWriteLocked {
    fn set_root_key(&mut self, content: &RootKeys) -> Result<()>;
    fn del_root_key(&mut self) -> Result<()>;
}

/// Modifying operations on persistent wallet data for encryption
pub trait WalletStorageEncryptionWrite {
    fn set_encryption_kdf_challenge(&mut self, salt: &KdfChallenge) -> Result<()>;
    fn del_encryption_kdf_challenge(&mut self) -> Result<()>;
    fn encrypt_root_keys(&mut self, new_encryption_key: &Option<SymmetricKey>) -> Result<()>;
}

/// Marker trait for types where read/write operations are run in a transaction
pub trait IsTransaction: is_transaction_seal::Seal {}

/// Operations on read-only transactions
pub trait TransactionRoLocked: WalletStorageReadLocked + IsTransaction {
    /// Close the transaction
    fn close(self);
}

/// Operations on read-only unlocked transactions
pub trait TransactionRoUnlocked: WalletStorageReadUnlocked + IsTransaction {
    /// Close the transaction
    fn close(self);
}

/// Operations on read-write transactions
pub trait TransactionRwLocked: WalletStorageWriteLocked + IsTransaction {
    /// Abort the transaction
    fn abort(self);

    /// Commit the transaction
    fn commit(self) -> Result<()>;
}

/// Operations on read-write transactions
pub trait TransactionRwUnlocked: WalletStorageWriteUnlocked + IsTransaction {
    /// Abort the transaction
    fn abort(self);

    /// Commit the transaction
    fn commit(self) -> Result<()>;
}

/// Support for transactions over wallet storage
pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRoLocked: TransactionRoLocked + 't;

    /// Associated read-only unlocked transaction type.
    type TransactionRoUnlocked: TransactionRoUnlocked + 't;

    /// Associated read-write transaction type.
    type TransactionRwLocked: TransactionRwLocked + 't;

    /// Associated read-write transaction type.
    type TransactionRwUnlocked: TransactionRwUnlocked + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRoLocked>;

    /// Start a read-only transaction.
    fn transaction_ro_unlocked<'s: 't>(&'s self) -> Result<Self::TransactionRoUnlocked>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self, size: Option<usize>) -> Result<Self::TransactionRwLocked>;

    /// Start a read-write transaction.
    fn transaction_rw_unlocked<'s: 't>(
        &'s self,
        size: Option<usize>,
    ) -> Result<Self::TransactionRwUnlocked>;
}

pub trait WalletStorage: WalletStorageWriteLocked + for<'tx> Transactional<'tx> + Send {}

pub type DefaultBackend = storage_sqlite::Sqlite;
pub type WalletStorageTxRwImpl<'st> = StoreTxRw<'st, storage_sqlite::Sqlite>;

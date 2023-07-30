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

use common::{
    address::Address,
    chain::{block::timestamp::BlockTimestamp, Destination, SignedTransaction},
};
use crypto::key::extended::ExtendedPublicKey;

use crate::{
    schema::Schema, TransactionRwLocked, TransactionRwUnlocked, Transactional, WalletStorage,
    WalletStorageEncryptionRead, WalletStorageEncryptionWrite, WalletStorageReadLocked,
    WalletStorageWriteLocked,
};

mod password;
use password::{challenge_to_sym_key, password_to_sym_key};

mod store_tx;
pub use store_tx::{StoreTxRo, StoreTxRoUnlocked, StoreTxRw, StoreTxRwUnlocked};
use wallet_types::{
    wallet_tx::WalletTx, AccountDerivationPathId, AccountId, AccountInfo, AccountKeyPurposeId,
    AccountWalletCreatedTxId, AccountWalletTxId, KeychainUsageState,
};

use self::store_tx::EncryptionState;

/// Store for wallet data, parametrized over the backend B
pub struct Store<B: storage::Backend> {
    storage: storage::Storage<B, Schema>,
    encryption_state: EncryptionState,
}

impl<B: storage::Backend> Store<B> {
    /// Create a new wallet storage
    pub fn new(backend: B) -> crate::Result<Self> {
        let storage: storage::Storage<B, Schema> =
            storage::Storage::new(backend).map_err(crate::Error::from)?;

        let mut storage = Self {
            storage,
            encryption_state: EncryptionState::Locked,
        };

        let challenge = storage.transaction_ro()?.get_encryption_key_kdf_challenge()?;
        if challenge.is_none() {
            storage.encryption_state = EncryptionState::Unlocked(None);
        }

        Ok(storage)
    }

    pub fn is_encrypted(&self) -> bool {
        match self.encryption_state {
            EncryptionState::Locked | EncryptionState::Unlocked(Some(_)) => true,
            EncryptionState::Unlocked(None) => false,
        }
    }

    /// Encrypts the root keys in the DB with the provided new_password
    /// expects that the wallet is already unlocked
    pub fn encrypt_private_keys(&mut self, new_password: &Option<String>) -> crate::Result<()> {
        let mut tx = self.transaction_rw_unlocked(None).map_err(crate::Error::from)?;
        let sym_key = match new_password {
            None => {
                tx.del_encryption_kdf_challenge()?;
                None
            }
            Some(pass) => {
                let (sym_key, kdf_challenge) = password_to_sym_key(pass)?;
                tx.set_encryption_kdf_challenge(&kdf_challenge).map_err(crate::Error::from)?;
                Some(sym_key)
            }
        };
        tx.encrypt_root_keys(&sym_key)?;
        tx.commit()?;

        self.encryption_state = EncryptionState::Unlocked(sym_key);

        Ok(())
    }

    /// Checks if the provided password can decrypt all of the stored private keys,
    /// stores the new encryption_key and updates the state to Unlocked
    /// Otherwise returns WalletInvalidPassword
    pub fn unlock_private_keys(&mut self, password: &String) -> crate::Result<()> {
        if self.encryption_state != EncryptionState::Locked {
            return Err(crate::Error::WalletAlreadyUnlocked);
        }

        let challenge = self.transaction_ro()?.get_encryption_key_kdf_challenge()?;

        match challenge {
            Some(kdf_challenge) => {
                let sym_key = challenge_to_sym_key(password, kdf_challenge)?;
                self.transaction_ro()?.check_can_decrypt_all_root_keys(&sym_key)?;
                self.encryption_state = EncryptionState::Unlocked(Some(sym_key));
            }
            None => {
                panic!("Wallet cannot be in a locked state if there is no password");
            }
        }

        Ok(())
    }

    /// Drops the encryption_key and sets the state to Locked
    /// Returns an error if no password is set
    pub fn lock_private_keys(&mut self) -> crate::Result<()> {
        match self.encryption_state {
            EncryptionState::Locked => Ok(()),
            EncryptionState::Unlocked(None) => Err(crate::Error::WalletLockedWithoutAPassword),
            EncryptionState::Unlocked(Some(_)) => {
                // will get zeroized on Drop
                self.encryption_state = EncryptionState::Locked;
                Ok(())
            }
        }
    }

    /// Dump raw database contents
    pub fn dump_raw(&self) -> crate::Result<storage::raw::StorageContents<Schema>> {
        self.storage.dump_raw().map_err(crate::Error::from)
    }
}

impl<B: storage::Backend> Clone for Store<B>
where
    B::Impl: Clone,
{
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            encryption_state: self.encryption_state.clone(),
        }
    }
}

impl<'tx, B: storage::Backend + 'tx> Transactional<'tx> for Store<B> {
    type TransactionRoLocked = StoreTxRo<'tx, B>;
    type TransactionRwLocked = StoreTxRw<'tx, B>;
    type TransactionRoUnlocked = StoreTxRoUnlocked<'tx, B>;
    type TransactionRwUnlocked = StoreTxRwUnlocked<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRoLocked> {
        self.storage
            .transaction_ro()
            .map_err(crate::Error::from)
            .map(|tx| StoreTxRo::new(tx))
    }

    fn transaction_ro_unlocked<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRoUnlocked> {
        match self.encryption_state {
            EncryptionState::Locked => Err(crate::Error::WalletLocked),
            EncryptionState::Unlocked(ref key) => self
                .storage
                .transaction_ro()
                .map_err(crate::Error::from)
                .map(|tx| StoreTxRoUnlocked::new(tx, key)),
        }
    }

    fn transaction_rw<'st: 'tx>(
        &'st self,
        size: Option<usize>,
    ) -> crate::Result<Self::TransactionRwLocked> {
        self.storage
            .transaction_rw(size)
            .map_err(crate::Error::from)
            .map(|tx| StoreTxRw::new(tx))
    }

    fn transaction_rw_unlocked<'st: 'tx>(
        &'st self,
        size: Option<usize>,
    ) -> crate::Result<Self::TransactionRwUnlocked> {
        match self.encryption_state {
            EncryptionState::Locked => Err(crate::Error::WalletLocked),
            EncryptionState::Unlocked(ref key) => self
                .storage
                .transaction_rw(size)
                .map_err(crate::Error::from)
                .map(|tx| StoreTxRwUnlocked::new(tx, key)),
        }
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

impl<B: storage::Backend> WalletStorageReadLocked for Store<B> {
    delegate_to_transaction! {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn get_transaction(&self, id: &AccountWalletTxId) -> crate::Result<Option<WalletTx>>;
        fn get_transactions(&self, account_id: &AccountId) -> crate::Result<Vec<(AccountWalletTxId, WalletTx)>>;
        fn get_user_transactions(&self) -> crate::Result<Vec<SignedTransaction>>;
        fn get_accounts_info(&self) -> crate::Result<BTreeMap<AccountId, AccountInfo>>;
        fn get_address(&self, id: &AccountDerivationPathId) -> crate::Result<Option<String>>;
        fn get_addresses(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountDerivationPathId, String>>;
        fn check_root_keys_sanity(&self) -> crate::Result<()>;
        fn get_keychain_usage_state(&self, id: &AccountKeyPurposeId) -> crate::Result<Option<KeychainUsageState>>;
        fn get_keychain_usage_states(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountKeyPurposeId, KeychainUsageState>>;
        fn get_public_key(&self, id: &AccountDerivationPathId) -> crate::Result<Option<ExtendedPublicKey>>;
        fn get_public_keys(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountDerivationPathId, ExtendedPublicKey>>;
        fn get_median_time(&self) -> crate::Result<Option<BlockTimestamp>>;
    }
}

impl<B: storage::Backend> WalletStorageWriteLocked for Store<B> {
    delegate_to_transaction! {
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn set_transaction(&mut self, id: &AccountWalletTxId, tx: &WalletTx) -> crate::Result<()>;
        fn del_transaction(&mut self, id: &AccountWalletTxId) -> crate::Result<()>;
        fn set_user_transaction(&mut self, id: &AccountWalletCreatedTxId, tx: &SignedTransaction) -> crate::Result<()>;
        fn del_user_transaction(&mut self, id: &AccountWalletCreatedTxId) -> crate::Result<()>;
        fn set_account(&mut self, id: &AccountId, content: &AccountInfo) -> crate::Result<()>;
        fn del_account(&mut self, id: &AccountId) -> crate::Result<()>;
        fn set_address(&mut self, id: &AccountDerivationPathId, address: &Address<Destination>) -> crate::Result<()>;
        fn del_address(&mut self, id: &AccountDerivationPathId) -> crate::Result<()>;
        fn set_keychain_usage_state(&mut self, id: &AccountKeyPurposeId, address: &KeychainUsageState) -> crate::Result<()>;
        fn del_keychain_usage_state(&mut self, id: &AccountKeyPurposeId) -> crate::Result<()>;
        fn set_public_key(&mut self, id: &AccountDerivationPathId, content: &ExtendedPublicKey) -> crate::Result<()>;
        fn det_public_key(&mut self, id: &AccountDerivationPathId) -> crate::Result<()>;
        fn set_median_time(&mut self, median_time: BlockTimestamp) -> crate::Result<()>;
    }
}

#[cfg(test)]
mod test;

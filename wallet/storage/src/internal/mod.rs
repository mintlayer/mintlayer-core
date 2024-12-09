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

use storage::raw;

use crate::{
    schema::Schema, TransactionRwUnlocked, Transactional, WalletStorageEncryptionRead,
    WalletStorageEncryptionWrite,
};

mod password;
use password::{challenge_to_sym_key, password_to_sym_key};

mod store_tx;
pub use store_tx::{StoreTxRo, StoreTxRoUnlocked, StoreTxRw, StoreTxRwUnlocked};

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

    /// Create a new wallet storage
    pub fn new_from_dump(backend: B, dump: raw::StorageContents<Schema>) -> crate::Result<Self> {
        let storage: storage::Storage<B, Schema> =
            storage::Storage::new_from_dump(backend, dump).map_err(crate::Error::from)?;

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

    pub fn is_locked(&self) -> bool {
        match self.encryption_state {
            EncryptionState::Locked => true,
            EncryptionState::Unlocked(_) => false,
        }
    }

    /// Encrypts the root keys in the DB with the provided new_password
    /// expects that the wallet is already unlocked
    pub fn encrypt_private_keys(&mut self, new_password: &Option<String>) -> crate::Result<()> {
        let mut tx = self.transaction_rw_unlocked(None)?;
        let sym_key = match new_password {
            None => {
                tx.del_encryption_kdf_challenge()?;
                None
            }
            Some(pass) => {
                let (sym_key, kdf_challenge) = password_to_sym_key(pass)?;
                tx.set_encryption_kdf_challenge(&kdf_challenge)?;
                Some(sym_key)
            }
        };
        tx.encrypt_root_keys(&sym_key)?;
        tx.encrypt_seed_phrase(&sym_key)?;
        tx.encrypt_standalone_private_keys(&sym_key)?;
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
        self.storage.transaction_ro()?.dump_raw().map_err(crate::Error::from)
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
        &'st mut self,
        size: Option<usize>,
    ) -> crate::Result<Self::TransactionRwLocked> {
        self.storage
            .transaction_rw(size)
            .map_err(crate::Error::from)
            .map(|tx| StoreTxRw::new(tx))
    }

    fn transaction_rw_unlocked<'st: 'tx>(
        &'st mut self,
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

#[cfg(test)]
mod test;

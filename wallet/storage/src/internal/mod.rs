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

use crypto::{
    kdf::{hash_from_challenge, hash_password, KdfChallenge, KdfConfig, KdfResult},
    symkey::SymmetricKeyKind,
};
use std::{collections::BTreeMap, num::NonZeroUsize};
use utils::ensure;

use common::address::Address;
use crypto::{
    kdf::argon2::Argon2Config, key::extended::ExtendedPublicKey, random::make_true_rng,
    symkey::SymmetricKey,
};

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

use self::store_tx::EncryptionState;

fn challenge_to_sym_key(
    password: &String,
    kdf_challenge: KdfChallenge,
) -> Result<SymmetricKey, crate::Error> {
    let KdfResult::Argon2id {
        hashed_password, ..
    } = hash_from_challenge(kdf_challenge, password.as_bytes())
        .map_err(|_| crate::Error::WalletInvalidPassword())?;

    let sym_key = SymmetricKey::from_raw_key(
        SymmetricKeyKind::XChacha20Poly1305,
        hashed_password.as_slice(),
    )
    .expect("must be correct size");

    Ok(sym_key)
}

fn password_to_sym_key(password: &String) -> crate::Result<(SymmetricKey, KdfChallenge)> {
    let mut rng = make_true_rng();
    let config = KdfConfig::Argon2id {
        // TODO: hardcoded values
        config: Argon2Config::new(700, 16, 2),
        hash_length: NonZeroUsize::new(32).expect("not 0"),
        salt_length: NonZeroUsize::new(32).expect("not 0"),
    };
    let kdf_result = hash_password(&mut rng, config, password.as_bytes())
        .map_err(|_| crate::Error::WalletInvalidPassword())?;
    let KdfResult::Argon2id {
        hashed_password, ..
    } = &kdf_result;

    let sym_key = SymmetricKey::from_raw_key(
        SymmetricKeyKind::XChacha20Poly1305,
        hashed_password.as_slice(),
    )
    .expect("must be correct size");

    let challenge = kdf_result.into_challenge();

    Ok((sym_key, challenge))
}

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

    /// Encrypts the root keys in the DB with the provided new_password
    /// expects that the wallet is already unlocked
    pub fn encrypt_private_keys(&mut self, new_password: &Option<String>) -> crate::Result<()> {
        ensure!(
            self.encryption_state != EncryptionState::Locked,
            crate::Error::WalletLocked()
        );

        let mut tx = self.transaction_rw(None).map_err(crate::Error::from)?;
        let sym_key = match new_password {
            None => None,
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
    pub fn unlock_private_keys(&mut self, password: &Option<String>) -> crate::Result<()> {
        if self.encryption_state != EncryptionState::Locked {
            return Ok(());
        }

        let challenge = self.transaction_ro()?.get_encryption_key_kdf_challenge()?;

        match (challenge, password) {
            (Some(kdf_challenge), Some(pass)) => {
                let sym_key = challenge_to_sym_key(pass, kdf_challenge)?;
                self.transaction_ro()?.check_can_decrypt_all_root_keys(&sym_key)?;
                self.encryption_state = EncryptionState::Unlocked(Some(sym_key));
            }
            (None, None) => {
                // will get zeroized on Drop
                self.encryption_state = EncryptionState::Unlocked(None);
            }
            // mismatch, user provided password but there is non in DB or reverse
            (Some(_), None) => return Err(crate::Error::WalletInvalidPassword()),
            (None, Some(_)) => return Err(crate::Error::WalletInvalidPassword()),
        }

        Ok(())
    }

    /// Drops the encryption_key and sets the state to Locked
    pub fn lock_private_keys(&mut self) {
        // will get zeroized on Drop
        self.encryption_state = EncryptionState::Locked;
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
    type TransactionRo = StoreTxRo<'tx, B>;
    type TransactionRw = StoreTxRw<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRo> {
        self.storage
            .transaction_ro()
            .map_err(crate::Error::from)
            .map(|tx| StoreTxRo::new(tx, &self.encryption_state))
    }

    fn transaction_rw<'st: 'tx>(
        &'st self,
        size: Option<usize>,
    ) -> crate::Result<Self::TransactionRw> {
        self.storage
            .transaction_rw(size)
            .map_err(crate::Error::from)
            .map(|tx| StoreTxRw::new(tx, &self.encryption_state))
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
        fn exactly_one_root_key(&self) -> crate::Result<bool>;
        fn check_can_decrypt_all_root_keys(&self, encryption_key: &SymmetricKey) -> crate::Result<()>;
        fn get_keychain_usage_state(&self, id: &AccountKeyPurposeId) -> crate::Result<Option<KeychainUsageState>>;
        fn get_keychain_usage_states(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountKeyPurposeId, KeychainUsageState>>;
        fn get_public_key(&self, id: &AccountDerivationPathId) -> crate::Result<Option<ExtendedPublicKey>>;
        fn get_public_keys(&self, account_id: &AccountId) -> crate::Result<BTreeMap<AccountDerivationPathId, ExtendedPublicKey>>;
        fn get_encryption_key_kdf_challenge(&self) -> crate::Result<Option<KdfChallenge>>;
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
        fn encrypt_root_keys(&mut self, new_encryption_key: &Option<SymmetricKey>) -> crate::Result<()>;
        fn set_keychain_usage_state(&mut self, id: &AccountKeyPurposeId, address: &KeychainUsageState) -> crate::Result<()>;
        fn del_keychain_usage_state(&mut self, id: &AccountKeyPurposeId) -> crate::Result<()>;
        fn set_public_key(&mut self, id: &AccountDerivationPathId, content: &ExtendedPublicKey) -> crate::Result<()>;
        fn det_public_key(&mut self, id: &AccountDerivationPathId) -> crate::Result<()>;
        fn set_encryption_kdf_challenge(&mut self, salt: &KdfChallenge) -> crate::Result<()>;
    }
}

#[cfg(test)]
mod test;

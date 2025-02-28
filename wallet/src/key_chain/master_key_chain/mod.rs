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

use crate::key_chain::{KeyChainError, KeyChainResult, DEFAULT_KEY_KIND};
use common::chain::ChainConfig;
use crypto::key::extended::ExtendedPrivateKey;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::hdkd::u31::U31;
use crypto::vrf::ExtendedVRFPrivateKey;
use std::sync::Arc;
use wallet_storage::{
    StoreTxRwUnlocked, WalletStorageReadLocked, WalletStorageReadUnlocked,
    WalletStorageWriteUnlocked,
};
use wallet_types::seed_phrase::{SerializableSeedPhrase, StoreSeedPhrase};

use super::{AccountKeyChainImplSoftware, DEFAULT_VRF_KEY_KIND};

#[derive(Clone, Debug)]
pub struct MasterKeyChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,
}

impl MasterKeyChain {
    pub fn mnemonic_to_root_key(
        mnemonic_str: &str,
        passphrase: Option<&str>,
    ) -> KeyChainResult<(
        ExtendedPrivateKey,
        ExtendedVRFPrivateKey,
        SerializableSeedPhrase,
    )> {
        let mnemonic = zeroize::Zeroizing::new(
            bip39::Mnemonic::parse(mnemonic_str).map_err(KeyChainError::Bip39)?,
        );
        let seed = zeroize::Zeroizing::new(mnemonic.to_seed(passphrase.unwrap_or("")));
        let root_key = ExtendedPrivateKey::new_master(seed.as_ref(), DEFAULT_KEY_KIND)?;
        let root_vrf_key = ExtendedVRFPrivateKey::new_master(seed.as_ref(), DEFAULT_VRF_KEY_KIND)?;
        Ok((
            root_key,
            root_vrf_key,
            SerializableSeedPhrase::new(
                mnemonic,
                zeroize::Zeroizing::new(passphrase.map(|p| p.to_owned())),
            ),
        ))
    }

    pub fn new_from_mnemonic<B: storage::Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRwUnlocked<B>,
        mnemonic_str: &str,
        passphrase: Option<&str>,
        save_seed_phrase: StoreSeedPhrase,
    ) -> KeyChainResult<Self> {
        // TODO: Do not store the master key here, store only the key relevant to the mintlayer
        // (see make_account_path)

        let (root_key, root_vrf_key, seed_phrase) =
            Self::mnemonic_to_root_key(mnemonic_str, passphrase)?;
        Self::new_from_root_key(
            chain_config,
            db_tx,
            root_key,
            root_vrf_key,
            save_seed_phrase.should_save().then_some(seed_phrase),
        )
    }

    fn new_from_root_key<B: storage::Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRwUnlocked<B>,
        root_key: ExtendedPrivateKey,
        root_vrf_key: ExtendedVRFPrivateKey,
        seed_phrase: Option<SerializableSeedPhrase>,
    ) -> KeyChainResult<Self> {
        if !root_key.get_derivation_path().is_root() {
            return Err(KeyChainError::KeyNotRoot);
        }

        let key_content = wallet_types::keys::RootKeys {
            root_key,
            root_vrf_key,
        };

        db_tx.set_root_key(&key_content)?;
        if let Some(seed_phrase) = seed_phrase {
            db_tx.set_seed_phrase(seed_phrase)?;
        }

        Ok(MasterKeyChain { chain_config })
    }

    pub fn load_root_key(
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let key = db_tx.get_root_key()?.ok_or(KeyChainError::KeyChainNotInitialized)?.root_key;

        Ok(key)
    }

    pub fn load_root_vrf_key(
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<ExtendedVRFPrivateKey> {
        let key = db_tx.get_root_key()?.ok_or(KeyChainError::KeyChainNotInitialized)?.root_vrf_key;

        Ok(key)
    }

    /// Creates a Master key chain, checks the database for an existing one
    pub fn new_from_existing_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
    ) -> KeyChainResult<Self> {
        db_tx.check_root_keys_sanity()?;
        Ok(MasterKeyChain { chain_config })
    }

    pub fn create_account_key_chain(
        &self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        account_index: U31,
        lookahead_size: u32,
    ) -> KeyChainResult<AccountKeyChainImplSoftware> {
        let root_key = Self::load_root_key(db_tx)?;
        let root_vrf_key = Self::load_root_vrf_key(db_tx)?;
        AccountKeyChainImplSoftware::new_from_root_key(
            self.chain_config.clone(),
            db_tx,
            root_key,
            root_vrf_key,
            account_index,
            lookahead_size,
        )
    }
}

// TODO: tests

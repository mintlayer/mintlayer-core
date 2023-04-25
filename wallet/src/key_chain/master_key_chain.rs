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

use crate::key_chain::account_key_chain::AccountKeyChain;
use crate::key_chain::{KeyChainError, KeyChainResult, DEFAULT_KEY_KIND, LOOKAHEAD_SIZE};
use common::chain::ChainConfig;
use crypto::key::extended::{ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::Derivable;
use std::sync::Arc;
use storage::Backend;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::{AccountId, RootKeyContent, RootKeyId};
use zeroize::Zeroize;

#[allow(dead_code)] // TODO remove
pub struct MasterKeyChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,
    /// The master key of this key chain from where all the keys are derived from
    // TODO implement encryption
    root_key: ExtendedPrivateKey,
}

impl MasterKeyChain {
    #[allow(dead_code)] // TODO remove
    pub fn mnemonic_to_root_key(
        mnemonic_str: &str,
        passphrase: Option<&str>,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let mut mnemonic = bip39::Mnemonic::parse(mnemonic_str).map_err(KeyChainError::Bip39)?;
        let mut seed = mnemonic.to_seed(passphrase.unwrap_or(""));
        let root_key = ExtendedPrivateKey::new_master(&seed, DEFAULT_KEY_KIND)?;
        // TODO(SECURITY) confirm that the mnemonic is erased on drop
        mnemonic.zeroize();
        seed.zeroize();
        Ok(root_key)
    }

    #[allow(dead_code)] // TODO remove
    pub fn new_from_mnemonic<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        mnemonic_str: &str,
        passphrase: Option<&str>,
    ) -> KeyChainResult<Self> {
        let root_key = Self::mnemonic_to_root_key(mnemonic_str, passphrase)?;
        Self::new_from_root_key(chain_config, db_tx, root_key)
    }

    #[allow(dead_code)] // TODO remove
    pub fn new_from_root_key<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        root_key: ExtendedPrivateKey,
    ) -> KeyChainResult<Self> {
        if !root_key.get_derivation_path().is_root() {
            return Err(KeyChainError::KeyNotRoot);
        }

        let key_id = RootKeyId::from(root_key.to_public_key());
        let key_content = RootKeyContent::from(root_key);

        db_tx.set_root_key(&key_id, &key_content)?;

        let root_key = key_content.into_key();

        Ok(MasterKeyChain {
            chain_config,
            root_key,
        })
    }

    /// Load the Master key chain from database and all the account key chains it derives
    #[allow(dead_code)] // TODO remove
    pub fn load_from_database<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &StoreTxRo<B>,
    ) -> KeyChainResult<Self> {
        let mut root_keys = db_tx.get_all_root_keys()?;

        // The current format supports a single root key
        if root_keys.len() != 1 {
            return Err(KeyChainError::OnlyOneRootKeyIsSupported);
        }

        let (_, key_content) =
            root_keys.pop_first().expect("Should not fail because it contains 1 key/value");

        let root_key = key_content.into_key();

        Ok(MasterKeyChain {
            chain_config,
            root_key,
        })
    }

    #[allow(dead_code)] // TODO remove
    pub fn create_account_key_chain<B: Backend>(
        &self,
        db_tx: &mut StoreTxRw<B>,
        account_index: ChildNumber,
    ) -> KeyChainResult<AccountKeyChain> {
        self.create_account_key_chain_with_lookahead(db_tx, account_index, LOOKAHEAD_SIZE)
    }

    #[allow(dead_code)] // TODO remove
    pub fn create_account_key_chain_with_lookahead<B: Backend>(
        &self,
        db_tx: &mut StoreTxRw<B>,
        account_index: ChildNumber,
        lookahead_size: u32,
    ) -> KeyChainResult<AccountKeyChain> {
        AccountKeyChain::new_from_root_key(
            self.chain_config.clone(),
            db_tx,
            &self.root_key,
            account_index,
            lookahead_size,
        )
    }

    #[allow(dead_code)] // TODO remove
    pub fn load_keychain_from_database<B: Backend>(
        &self,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> KeyChainResult<AccountKeyChain> {
        AccountKeyChain::load_from_database(self.chain_config.clone(), db_tx, id)
    }

    #[allow(dead_code)] // TODO remove
                        // TODO make it return a reference
    pub fn get_root_public_key(&self) -> ExtendedPublicKey {
        self.root_key.to_public_key()
    }

    #[allow(dead_code)] // TODO remove
    pub fn get_root_private_key(&self) -> &ExtendedPrivateKey {
        &self.root_key
    }
}

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
use crypto::key::extended::ExtendedPrivateKey;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::hdkd::u31::U31;
use itertools::Itertools;
use std::sync::Arc;
use utils::ensure;
use wallet_storage::{StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::{RootKeyContent, RootKeyId};
use zeroize::Zeroize;

pub struct MasterKeyChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,
}

impl MasterKeyChain {
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

    pub fn new_from_mnemonic<B: storage::Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        mnemonic_str: &str,
        passphrase: Option<&str>,
    ) -> KeyChainResult<Self> {
        // TODO: Do not store the master key here, store only the key relevant to the mintlayer
        // (see make_account_path)

        let root_key = Self::mnemonic_to_root_key(mnemonic_str, passphrase)?;
        Self::new_from_root_key(chain_config, db_tx, root_key)
    }

    pub fn new_from_root_key<B: storage::Backend>(
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

        Ok(MasterKeyChain { chain_config })
    }

    pub fn load_root_key(db_tx: &impl WalletStorageRead) -> KeyChainResult<ExtendedPrivateKey> {
        let key = db_tx
            .get_all_root_keys()?
            .into_values()
            .exactly_one()
            .map_err(|_| KeyChainError::OnlyOneRootKeyIsSupported)?
            .into_key();

        Ok(key)
    }

    /// Creates a Master key chain, checks the database for an existing one
    pub fn existing_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageRead,
    ) -> KeyChainResult<Self> {
        ensure!(
            db_tx.exactly_one_root_key()?,
            KeyChainError::OnlyOneRootKeyIsSupported
        );
        // The current format supports a single root key
        Ok(MasterKeyChain { chain_config })
    }

    pub fn create_account_key_chain<B: storage::Backend>(
        &self,
        db_tx: &mut StoreTxRw<B>,
        account_index: U31,
    ) -> KeyChainResult<AccountKeyChain> {
        let root_key = Self::load_root_key(db_tx)?;
        AccountKeyChain::new_from_root_key(
            self.chain_config.clone(),
            db_tx,
            root_key,
            account_index,
            LOOKAHEAD_SIZE,
        )
    }
}

// TODO: tests

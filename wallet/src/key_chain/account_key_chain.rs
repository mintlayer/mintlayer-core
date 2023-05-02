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

use crate::key_chain::leaf_key_chain::LeafKeyChain;
use crate::key_chain::{make_account_path, KeyChainError, KeyChainResult};
use common::address::pubkeyhash::PublicKeyHash;
use common::address::Address;
use common::chain::ChainConfig;
use crypto::key::extended::{ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::PublicKey;
use std::sync::Arc;
use storage::Backend;
use utils::const_value::ConstValue;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::keys::KeyPurpose;
use wallet_types::{AccountId, AccountInfo, DeterministicAccountInfo};

#[allow(dead_code)] // TODO remove
/// This key chain contains a pool of pre-generated keys and addresses for the usage in a wallet
pub struct AccountKeyChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The account key from which all the addresses are derived
    account_pubkey: ConstValue<ExtendedPublicKey>,

    /// The master/root key that this account key was derived from
    root_hierarchy_key: ConstValue<Option<ExtendedPublicKey>>,

    /// Key chain for receiving funds
    receiving_key_chain: LeafKeyChain,

    /// Key chain for change addresses
    change_key_chain: LeafKeyChain,

    /// The number of unused addresses that need to be checked after the last used address
    lookahead_size: u32,
}

impl AccountKeyChain {
    pub fn new_from_root_key<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        root_key: &ExtendedPrivateKey,
        index: ChildNumber,
        lookahead_size: u32,
    ) -> KeyChainResult<AccountKeyChain> {
        let account_path = make_account_path(&chain_config, index);

        let account_privkey = root_key.clone().derive_absolute_path(&account_path)?;

        let account_pubkey = account_privkey.to_public_key();

        let account_id = AccountId::new_from_xpub(&account_pubkey);

        let receiving_key_chain = LeafKeyChain::new_empty(
            chain_config.clone(),
            account_id.clone(),
            KeyPurpose::ReceiveFunds,
            account_pubkey
                .clone()
                .derive_child(KeyPurpose::ReceiveFunds.get_deterministic_index())?,
            lookahead_size,
        );
        receiving_key_chain.save_usage_state(db_tx)?;

        let change_key_chain = LeafKeyChain::new_empty(
            chain_config.clone(),
            account_id,
            KeyPurpose::Change,
            account_pubkey
                .clone()
                .derive_child(KeyPurpose::Change.get_deterministic_index())?,
            lookahead_size,
        );
        change_key_chain.save_usage_state(db_tx)?;

        let mut new_account = AccountKeyChain {
            chain_config,
            account_pubkey: account_pubkey.into(),
            root_hierarchy_key: Some(root_key.to_public_key()).into(),
            receiving_key_chain,
            change_key_chain,
            lookahead_size,
        };

        db_tx.set_account(
            &new_account.get_account_id(),
            &new_account.get_account_info(),
        )?;

        new_account.top_up_all(db_tx)?;

        Ok(new_account)
    }

    /// Load the key chain from the database
    pub fn load_from_database<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> KeyChainResult<Self> {
        let account_info =
            db_tx.get_account(id)?.ok_or(KeyChainError::NoAccountFound(id.clone()))?;

        let AccountInfo::Deterministic(account_info) = account_info;

        let account_pubkey = account_info.get_account_key().clone();

        let (receiving_key_chain, change_key_chain) =
            LeafKeyChain::load_leaf_keys(chain_config.clone(), &account_info, db_tx, id)?;

        Ok(AccountKeyChain {
            chain_config,
            account_pubkey: account_pubkey.into(),
            root_hierarchy_key: account_info.get_root_hierarchy_key().clone().into(),
            receiving_key_chain,
            change_key_chain,
            lookahead_size: account_info.get_lookahead_size(),
        })
    }

    pub fn get_account_id(&self) -> AccountId {
        AccountId::new_from_xpub(&self.account_pubkey)
    }

    pub fn get_account_key(&self) -> ExtendedPublicKey {
        self.account_pubkey.clone().take()
    }

    /// Issue a new address that hasn't been used before
    pub fn issue_address<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> KeyChainResult<Address> {
        self.get_leaf_key_chain_mut(purpose).issue_address(db_tx)
    }

    /// Issue a new derived key that hasn't been used before
    pub fn issue_key<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> KeyChainResult<ExtendedPublicKey> {
        self.get_leaf_key_chain_mut(purpose).issue_key(db_tx)
    }

    /// Get the private key that corresponds to the provided public key
    #[allow(dead_code)] // TODO remove
    pub fn get_private_key(
        &self,
        parent_key: &ExtendedPrivateKey,
        requested_key: &ExtendedPublicKey,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let derived_key =
            parent_key.clone().derive_absolute_path(requested_key.get_derivation_path())?;
        if &derived_key.to_public_key() == requested_key {
            Ok(derived_key)
        } else {
            Err(KeyChainError::KeysNotInSameHierarchy)
        }
    }

    /// Get the leaf key chain for a particular key purpose
    pub fn get_leaf_key_chain(&self, purpose: KeyPurpose) -> &LeafKeyChain {
        match purpose {
            KeyPurpose::ReceiveFunds => &self.receiving_key_chain,
            KeyPurpose::Change => &self.change_key_chain,
        }
    }

    /// Get the mutable leaf key chain for a particular key purpose. This is used internally with
    /// database persistence done externally.
    fn get_leaf_key_chain_mut(&mut self, purpose: KeyPurpose) -> &mut LeafKeyChain {
        match purpose {
            KeyPurpose::ReceiveFunds => &mut self.receiving_key_chain,
            KeyPurpose::Change => &mut self.change_key_chain,
        }
    }

    // Return true if the provided public key belongs to this key chain
    pub fn is_public_key_mine(&self, public_key: &PublicKey) -> bool {
        for purpose in KeyPurpose::ALL {
            if self.get_leaf_key_chain(purpose).is_public_key_mine(public_key) {
                return true; // Return early to avoid checking all leaf key chains
            }
        }
        false
    }

    // Return true if the provided public key hash belongs to this key chain
    pub fn is_public_key_hash_mine(&self, pubkey_hash: &PublicKeyHash) -> bool {
        for purpose in KeyPurpose::ALL {
            if self.get_leaf_key_chain(purpose).is_public_key_hash_mine(pubkey_hash) {
                return true; // Return early to avoid checking all leaf key chains
            }
        }
        false
    }

    /// Derive addresses until there are lookahead unused ones
    pub fn top_up_all<B: Backend>(&mut self, db_tx: &mut StoreTxRw<B>) -> KeyChainResult<()> {
        for purpose in KeyPurpose::ALL {
            self.get_leaf_key_chain_mut(purpose).top_up(db_tx)?;
        }
        Ok(())
    }

    pub fn get_account_info(&self) -> AccountInfo {
        AccountInfo::Deterministic(DeterministicAccountInfo::new(
            self.root_hierarchy_key.clone().take(),
            self.account_pubkey.clone().take(),
            self.lookahead_size,
        ))
    }

    pub fn get_lookahead_size(&self) -> u32 {
        self.lookahead_size
    }

    pub fn set_lookahead_size<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        lookahead_size: u32,
    ) -> KeyChainResult<()> {
        self.lookahead_size = lookahead_size;
        db_tx.set_account(&self.get_account_id(), &self.get_account_info())?;
        for purpose in KeyPurpose::ALL {
            self.get_leaf_key_chain_mut(purpose).set_lookahead_size(lookahead_size);
        }
        self.top_up_all(db_tx)
    }

    /// Marks a public key as being used. Returns true if a key was found and set to used.
    pub fn mark_public_key_as_used<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        public_key: &PublicKey,
    ) -> KeyChainResult<bool> {
        for purpose in KeyPurpose::ALL {
            let leaf_keys = self.get_leaf_key_chain_mut(purpose);
            if leaf_keys.mark_pubkey_as_used(db_tx, public_key)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn mark_public_key_hash_as_used<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        pub_key_hash: &PublicKeyHash,
    ) -> KeyChainResult<bool> {
        for purpose in KeyPurpose::ALL {
            let leaf_keys = self.get_leaf_key_chain_mut(purpose);
            if leaf_keys.mark_pub_key_hash_as_used(db_tx, pub_key_hash)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

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

use crate::key_chain::leaf_key_chain::LeafKeySoftChain;
use crate::key_chain::with_purpose::WithPurpose;
use crate::key_chain::{make_account_path, KeyChainError, KeyChainResult};
use common::address::pubkeyhash::PublicKeyHash;
use common::address::Address;
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::{ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::hdkd::derivation_path::DerivationPath;
use crypto::key::hdkd::u31::U31;
use crypto::key::PublicKey;
use crypto::vrf::ExtendedVRFPrivateKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use utils::const_value::ConstValue;
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteLocked,
};
use wallet_types::keys::KeyPurpose;
use wallet_types::{AccountId, AccountInfo, KeychainUsageState};

use super::MasterKeyChain;

/// This key chain contains a pool of pre-generated keys and addresses for the usage in a wallet
pub struct AccountKeyChain {
    chain_config: Arc<ChainConfig>,

    account_index: U31,

    /// The account public key from which all the addresses are derived
    account_public_key: ConstValue<ExtendedPublicKey>,

    /// Key chains for receiving and change funds
    sub_chains: WithPurpose<LeafKeySoftChain>,

    /// The number of unused addresses that need to be checked after the last used address
    lookahead_size: ConstValue<u32>,
}

impl AccountKeyChain {
    pub fn new_from_root_key(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut impl WalletStorageWriteLocked,
        root_key: ExtendedPrivateKey,
        account_index: U31,
        lookahead_size: u32,
    ) -> KeyChainResult<AccountKeyChain> {
        let account_path = make_account_path(&chain_config, account_index);

        let account_privkey = root_key.derive_absolute_path(&account_path)?;

        let account_pubkey = account_privkey.to_public_key();

        let account_id = AccountId::new_from_xpub(&account_pubkey);

        let receiving_key_chain = LeafKeySoftChain::new_empty(
            chain_config.clone(),
            account_id.clone(),
            KeyPurpose::ReceiveFunds,
            account_pubkey
                .clone()
                .derive_child(KeyPurpose::ReceiveFunds.get_deterministic_index())?,
        );
        receiving_key_chain.save_usage_state(db_tx)?;

        let change_key_chain = LeafKeySoftChain::new_empty(
            chain_config.clone(),
            account_id,
            KeyPurpose::Change,
            account_pubkey
                .clone()
                .derive_child(KeyPurpose::Change.get_deterministic_index())?,
        );
        change_key_chain.save_usage_state(db_tx)?;

        let sub_chains = WithPurpose::new(receiving_key_chain, change_key_chain);

        let mut new_account = AccountKeyChain {
            chain_config,
            account_index,
            account_public_key: account_pubkey.into(),
            sub_chains,
            lookahead_size: lookahead_size.into(),
        };

        new_account.top_up_all(db_tx)?;

        Ok(new_account)
    }

    fn derive_account_private_key(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let account_path = make_account_path(&self.chain_config, self.account_index);

        let root_key = MasterKeyChain::load_root_key(db_tx)?.derive_absolute_path(&account_path)?;
        Ok(root_key)
    }

    fn derive_account_private_vrf_key(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<ExtendedVRFPrivateKey> {
        let account_path = make_account_path(&self.chain_config, self.account_index);

        let root_key =
            MasterKeyChain::load_root_vrf_key(db_tx)?.derive_absolute_path(&account_path)?;
        Ok(root_key)
    }

    /// Load the key chain from the database
    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
        account_info: &AccountInfo,
    ) -> KeyChainResult<Self> {
        let pubkey_id = account_info.account_key().clone().into();

        let sub_chains =
            LeafKeySoftChain::load_leaf_keys(chain_config.clone(), account_info, db_tx, id)?;

        Ok(AccountKeyChain {
            chain_config,
            account_index: account_info.account_index(),
            account_public_key: pubkey_id,
            sub_chains,
            lookahead_size: account_info.lookahead_size().into(),
        })
    }

    pub fn account_index(&self) -> U31 {
        self.account_index
    }

    pub fn get_account_id(&self) -> AccountId {
        AccountId::new_from_xpub(&self.account_public_key)
    }

    pub fn account_public_key(&self) -> &ExtendedPublicKey {
        self.account_public_key.as_ref()
    }

    /// Issue a new address that hasn't been used before
    pub fn issue_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> KeyChainResult<(ChildNumber, Address<Destination>)> {
        let lookahead_size = self.lookahead_size();
        let (index, _key, address) =
            self.get_leaf_key_chain_mut(purpose).issue_new(db_tx, lookahead_size)?;
        Ok((index, address))
    }

    /// Issue a new derived key that hasn't been used before
    pub fn issue_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> KeyChainResult<ExtendedPublicKey> {
        let lookahead_size = self.lookahead_size();
        let (_index, key, _address) =
            self.get_leaf_key_chain_mut(purpose).issue_new(db_tx, lookahead_size)?;
        Ok(key)
    }

    /// Get the private key that corresponds to the provided public key
    fn get_private_key(
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

    pub fn derive_private_key(
        &self,
        requested_key: &ExtendedPublicKey,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let xpriv = self.derive_account_private_key(db_tx)?;
        Self::get_private_key(&xpriv, requested_key)
    }

    pub fn get_private_key_for_destination(
        &self,
        destination: &Destination,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<Option<ExtendedPrivateKey>> {
        let xpriv = self.derive_account_private_key(db_tx)?;
        for purpose in KeyPurpose::ALL {
            let leaf_key = self.get_leaf_key_chain(purpose);
            if let Some(xpub) = leaf_key
                .get_child_num_from_destination(destination)
                .and_then(|child_num| leaf_key.get_derived_xpub(child_num))
            {
                return Self::get_private_key(&xpriv, xpub).map(Option::Some);
            }
        }
        Ok(None)
    }

    pub fn get_private_key_for_path(
        &self,
        path: &DerivationPath,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let xpriv = self.derive_account_private_key(db_tx)?;
        xpriv.derive_absolute_path(path).map_err(KeyChainError::Derivation)
    }

    pub fn get_private_vrf_key_for_path(
        &self,
        path: &DerivationPath,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<ExtendedVRFPrivateKey> {
        let xpriv = self.derive_account_private_vrf_key(db_tx)?;
        xpriv.derive_absolute_path(path).map_err(KeyChainError::Derivation)
    }

    /// Get the leaf key chain for a particular key purpose
    pub fn get_leaf_key_chain(&self, purpose: KeyPurpose) -> &LeafKeySoftChain {
        self.sub_chains.get_for(purpose)
    }

    /// Get the mutable leaf key chain for a particular key purpose. This is used internally with
    /// database persistence done externally.
    fn get_leaf_key_chain_mut(&mut self, purpose: KeyPurpose) -> &mut LeafKeySoftChain {
        self.sub_chains.mut_for(purpose)
    }

    // Return true if the provided destination belongs to this key chain
    pub fn is_destination_mine(&self, destination: &Destination) -> bool {
        KeyPurpose::ALL
            .iter()
            .any(|p| self.get_leaf_key_chain(*p).is_destination_mine(destination))
    }

    // Return true if the provided public key belongs to this key chain
    pub fn is_public_key_mine(&self, public_key: &PublicKey) -> bool {
        KeyPurpose::ALL
            .iter()
            .any(|purpose| self.get_leaf_key_chain(*purpose).is_public_key_mine(public_key))
    }

    // Return true if the provided public key hash belongs to this key chain
    pub fn is_public_key_hash_mine(&self, pubkey_hash: &PublicKeyHash) -> bool {
        KeyPurpose::ALL
            .iter()
            .any(|purpose| self.get_leaf_key_chain(*purpose).is_public_key_hash_mine(pubkey_hash))
    }

    /// Derive addresses until there are lookahead unused ones
    pub fn top_up_all(&mut self, db_tx: &mut impl WalletStorageWriteLocked) -> KeyChainResult<()> {
        let lookahead_size = self.lookahead_size();
        KeyPurpose::ALL.iter().try_for_each(|purpose| {
            self.get_leaf_key_chain_mut(*purpose).top_up(db_tx, lookahead_size)
        })
    }

    pub fn lookahead_size(&self) -> u32 {
        *self.lookahead_size
    }

    /// Marks a public key as being used. Returns true if a key was found and set to used.
    pub fn mark_public_key_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key: &PublicKey,
    ) -> KeyChainResult<bool> {
        let lookahead_size = self.lookahead_size();
        for purpose in KeyPurpose::ALL {
            let leaf_keys = self.get_leaf_key_chain_mut(purpose);
            if leaf_keys.mark_pubkey_as_used(db_tx, public_key, lookahead_size)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn mark_public_key_hash_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        pub_key_hash: &PublicKeyHash,
    ) -> KeyChainResult<bool> {
        let lookahead_size = self.lookahead_size();
        for purpose in KeyPurpose::ALL {
            let leaf_keys = self.get_leaf_key_chain_mut(purpose);
            if leaf_keys.mark_pub_key_hash_as_used(db_tx, pub_key_hash, lookahead_size)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn get_all_issued_addresses(&self) -> BTreeMap<ChildNumber, Address<Destination>> {
        self.get_leaf_key_chain(KeyPurpose::ReceiveFunds).get_all_issued_addresses()
    }

    pub fn get_addresses_usage_state(&self) -> &KeychainUsageState {
        self.get_leaf_key_chain(KeyPurpose::ReceiveFunds).usage_state()
    }
}

#[cfg(test)]
mod tests;

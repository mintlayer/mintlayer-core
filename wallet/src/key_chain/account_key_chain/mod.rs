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
use common::address::{Address, RpcAddress};
use common::chain::classic_multisig::ClassicMultisigChallenge;
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::{ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::hdkd::u31::U31;
use crypto::key::{PrivateKey, PublicKey};
use crypto::vrf::{ExtendedVRFPrivateKey, ExtendedVRFPublicKey, VRFPublicKey};
use std::collections::BTreeMap;
use std::sync::Arc;
use utils::const_value::ConstValue;
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteLocked,
    WalletStorageWriteUnlocked,
};
use wallet_types::account_id::{AccountPrefixedId, AccountPublicKey};
use wallet_types::account_info::{
    StandaloneAddressDetails, StandaloneAddresses, StandaloneMultisig, StandaloneWatchOnlyKey,
};
use wallet_types::keys::KeyPurpose;
use wallet_types::{AccountId, AccountInfo, KeychainUsageState};

use super::vrf_key_chain::{EmptyVrfKeyChain, VrfKeyChain, VrfKeySoftChain};
use super::{
    make_path_to_vrf_key, AccountKeyChains, MasterKeyChain, VRFAccountKeyChains, VRF_INDEX,
};

/// This key chain contains a pool of pre-generated keys and addresses for the usage in a wallet
pub struct AccountKeyChainImpl<V> {
    chain_config: Arc<ChainConfig>,

    account_index: U31,

    /// The account public key from which all the addresses are derived
    account_public_key: ConstValue<ExtendedPublicKey>,

    /// Key chains for receiving and change funds
    sub_chains: WithPurpose<LeafKeySoftChain>,

    /// VRF key chain
    vrf_chain: V,

    /// Standalone watch only keys added by the user not derived from this account's chain
    standalone_watch_only_keys: BTreeMap<Destination, StandaloneWatchOnlyKey>,

    /// Standalone multisig keys added by the user not derived from this account's chain
    standalone_multisig_keys: BTreeMap<Destination, StandaloneMultisig>,

    /// Standalone private keys added by the user not derived from this account's chain
    standalone_private_keys: BTreeMap<Destination, (Option<String>, AccountPublicKey)>,

    /// The number of unused addresses that need to be checked after the last used address
    lookahead_size: ConstValue<u32>,
}

impl AccountKeyChainImpl<VrfKeySoftChain> {
    pub fn new_from_root_key(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut impl WalletStorageWriteLocked,
        root_key: ExtendedPrivateKey,
        root_vrf_key: ExtendedVRFPrivateKey,
        account_index: U31,
        lookahead_size: u32,
    ) -> KeyChainResult<Self> {
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
            account_id.clone(),
            KeyPurpose::Change,
            account_pubkey
                .clone()
                .derive_child(KeyPurpose::Change.get_deterministic_index())?,
        );
        change_key_chain.save_usage_state(db_tx)?;

        let sub_chains = WithPurpose::new(receiving_key_chain, change_key_chain);
        let legacy_key_path = make_path_to_vrf_key(&chain_config, account_index);
        let legacy_vrf_key =
            root_vrf_key.clone().derive_absolute_path(&legacy_key_path)?.to_public_key();

        let account_vrf_pub_key = root_vrf_key
            .derive_absolute_path(&account_path)?
            .derive_child(VRF_INDEX)?
            .to_public_key();

        db_tx.set_account_vrf_public_keys(
            &account_id,
            &wallet_types::account_info::AccountVrfKeys {
                account_vrf_key: account_vrf_pub_key.clone(),
                legacy_vrf_key: legacy_vrf_key.clone(),
            },
        )?;

        let vrf_chain = VrfKeySoftChain::new_empty(
            chain_config.clone(),
            account_id,
            account_vrf_pub_key.clone(),
            legacy_vrf_key,
        );
        vrf_chain.save_usage_state(db_tx)?;

        let mut new_account = Self {
            chain_config,
            account_index,
            account_public_key: account_pubkey.into(),
            sub_chains,
            vrf_chain,
            standalone_watch_only_keys: BTreeMap::new(),
            standalone_multisig_keys: BTreeMap::new(),
            standalone_private_keys: BTreeMap::new(),
            lookahead_size: lookahead_size.into(),
        };

        new_account.top_up_all(db_tx)?;

        Ok(new_account)
    }
}

impl AccountKeyChainImpl<EmptyVrfKeyChain> {
    pub fn new_from_hardware_key(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut impl WalletStorageWriteLocked,
        account_pubkey: ExtendedPublicKey,
        account_index: U31,
        lookahead_size: u32,
    ) -> KeyChainResult<Self> {
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
            account_id.clone(),
            KeyPurpose::Change,
            account_pubkey
                .clone()
                .derive_child(KeyPurpose::Change.get_deterministic_index())?,
        );
        change_key_chain.save_usage_state(db_tx)?;

        let sub_chains = WithPurpose::new(receiving_key_chain, change_key_chain);

        let vrf_chain = EmptyVrfKeyChain {};

        let mut new_account = Self {
            chain_config,
            account_index,
            account_public_key: account_pubkey.into(),
            sub_chains,
            vrf_chain,
            standalone_watch_only_keys: BTreeMap::new(),
            standalone_multisig_keys: BTreeMap::new(),
            standalone_private_keys: BTreeMap::new(),
            lookahead_size: lookahead_size.into(),
        };

        new_account.top_up_all(db_tx)?;

        Ok(new_account)
    }
}

impl<V> AccountKeyChainImpl<V> {
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

    /// Get the private key that corresponds to the provided public key
    fn get_vrf_private_key(
        parent_key: &ExtendedVRFPrivateKey,
        requested_key: &ExtendedVRFPublicKey,
    ) -> KeyChainResult<ExtendedVRFPrivateKey> {
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

    /// Get the leaf key chain for a particular key purpose
    pub fn get_leaf_key_chain(&self, purpose: KeyPurpose) -> &LeafKeySoftChain {
        self.sub_chains.get_for(purpose)
    }

    /// Get the mutable leaf key chain for a particular key purpose. This is used internally with
    /// database persistence done externally.
    fn get_leaf_key_chain_mut(&mut self, purpose: KeyPurpose) -> &mut LeafKeySoftChain {
        self.sub_chains.mut_for(purpose)
    }
}

impl<V: VrfKeyChain> AccountKeyChains for AccountKeyChainImpl<V> {
    /// Load the key chain from the database
    fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
        account_info: &AccountInfo,
    ) -> KeyChainResult<Self> {
        let pubkey_id = account_info.account_key().clone().into();

        let sub_chains = LeafKeySoftChain::load_leaf_keys(
            chain_config.clone(),
            account_info.account_key(),
            db_tx,
            id,
        )?;

        let vrf_chain = V::load_from_database(
            chain_config.clone(),
            db_tx,
            id,
            account_info.lookahead_size(),
        )?;

        let standalone_watch_only_keys = db_tx.get_account_standalone_watch_only_keys(
            &AccountId::new_from_xpub(account_info.account_key()),
        )?;

        let standalone_multisig_keys = db_tx.get_account_standalone_multisig_keys(
            &AccountId::new_from_xpub(account_info.account_key()),
        )?;

        let standalone_private_keys = db_tx.get_account_standalone_private_keys(
            &AccountId::new_from_xpub(account_info.account_key()),
        )?;

        let standalone_private_keys = standalone_private_keys
            .into_iter()
            .flat_map(|(acc_public_key, label)| {
                let public_key = acc_public_key.clone().into_item_id();
                let public_key_hash = (&public_key).into();
                [
                    (
                        Destination::PublicKey(public_key),
                        (label.clone(), acc_public_key.clone()),
                    ),
                    (
                        Destination::PublicKeyHash(public_key_hash),
                        (label, acc_public_key),
                    ),
                ]
            })
            .collect();

        Ok(Self {
            chain_config,
            account_index: account_info.account_index(),
            account_public_key: pubkey_id,
            sub_chains,
            vrf_chain,
            standalone_watch_only_keys,
            standalone_multisig_keys,
            standalone_private_keys,
            lookahead_size: account_info.lookahead_size().into(),
        })
    }
    fn find_public_key(&self, destination: &Destination) -> Option<super::FoundPubKey> {
        for purpose in KeyPurpose::ALL {
            let leaf_key = self.get_leaf_key_chain(purpose);
            if let Some(xpub) = leaf_key
                .get_child_num_from_destination(destination)
                .and_then(|child_num| leaf_key.get_derived_xpub(child_num))
            {
                return Some(super::FoundPubKey::Hierarchy(xpub.clone()));
            }
        }

        self.standalone_private_keys
            .get(destination)
            .map(|(_, acc_public_key)| super::FoundPubKey::Standalone(acc_public_key.clone()))
    }

    fn find_multisig_challenge(
        &self,
        destination: &Destination,
    ) -> Option<&ClassicMultisigChallenge> {
        self.get_multisig_challenge(destination)
    }

    fn account_index(&self) -> U31 {
        self.account_index
    }

    fn get_account_id(&self) -> AccountId {
        AccountId::new_from_xpub(&self.account_public_key)
    }

    fn account_public_key(&self) -> &ExtendedPublicKey {
        self.account_public_key.as_ref()
    }

    /// Return the next unused address and don't mark it as issued
    fn next_unused_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> KeyChainResult<(ChildNumber, Address<Destination>)> {
        let (index, _key, address) = self.get_leaf_key_chain_mut(purpose).next_unused(db_tx)?;
        Ok((index, address))
    }

    /// Issue a new address that hasn't been used before
    fn issue_address(
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
    fn issue_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> KeyChainResult<ExtendedPublicKey> {
        let lookahead_size = self.lookahead_size();
        let (_index, key, _address) =
            self.get_leaf_key_chain_mut(purpose).issue_new(db_tx, lookahead_size)?;
        Ok(key)
    }

    /// Reload the sub chain keys from DB to restore the cache
    /// Should be called after issuing a new key but not using committing it to the DB
    fn reload_keys(&mut self, db_tx: &impl WalletStorageReadLocked) -> KeyChainResult<()> {
        self.sub_chains = LeafKeySoftChain::load_leaf_keys(
            self.chain_config.clone(),
            &self.account_public_key,
            db_tx,
            &self.get_account_id(),
        )?;

        self.vrf_chain = V::load_from_database(
            self.chain_config.clone(),
            db_tx,
            &self.get_account_id(),
            self.lookahead_size(),
        )?;

        Ok(())
    }

    fn has_private_key_for_destination(&self, destination: &Destination) -> bool {
        self.is_destination_mine(destination)
            || self.standalone_private_keys.contains_key(destination)
    }

    // Return true if the provided destination belongs to this key chain
    fn is_destination_mine(&self, destination: &Destination) -> bool {
        KeyPurpose::ALL
            .iter()
            .any(|p| self.get_leaf_key_chain(*p).is_destination_mine(destination))
    }

    // Return true if the provided public key belongs to this key chain
    fn is_public_key_mine(&self, public_key: &PublicKey) -> bool {
        KeyPurpose::ALL
            .iter()
            .any(|purpose| self.get_leaf_key_chain(*purpose).is_public_key_mine(public_key))
    }

    // Return true if the provided public key hash belongs to this key chain
    fn is_public_key_hash_mine(&self, pubkey_hash: &PublicKeyHash) -> bool {
        KeyPurpose::ALL
            .iter()
            .any(|purpose| self.get_leaf_key_chain(*purpose).is_public_key_hash_mine(pubkey_hash))
    }

    // Return true if the provided public key hash is one the standalone added keys
    fn is_public_key_hash_watched(&self, pubkey_hash: PublicKeyHash) -> bool {
        let dest = Destination::PublicKeyHash(pubkey_hash);
        self.standalone_watch_only_keys.contains_key(&dest)
            || self.standalone_private_keys.contains_key(&dest)
    }

    // Return true if the provided public key hash belongs to this key chain
    // or is one the standalone added keys
    fn is_public_key_hash_mine_or_watched(&self, pubkey_hash: PublicKeyHash) -> bool {
        self.is_public_key_hash_mine(&pubkey_hash) || self.is_public_key_hash_watched(pubkey_hash)
    }

    /// Find the corresponding public key for a given public key hash
    fn get_public_key_from_public_key_hash(
        &self,
        pubkey_hash: &PublicKeyHash,
    ) -> Option<PublicKey> {
        KeyPurpose::ALL.iter().find_map(|purpose| {
            self.get_leaf_key_chain(*purpose)
                .get_public_key_from_public_key_hash(pubkey_hash)
        })
    }

    /// Derive addresses until there are lookahead unused ones
    fn top_up_all(&mut self, db_tx: &mut impl WalletStorageWriteLocked) -> KeyChainResult<()> {
        let lookahead_size = self.lookahead_size();
        KeyPurpose::ALL.iter().try_for_each(|purpose| {
            self.get_leaf_key_chain_mut(*purpose).top_up(db_tx, lookahead_size)
        })?;
        self.vrf_chain.top_up(lookahead_size)
    }

    fn lookahead_size(&self) -> u32 {
        *self.lookahead_size
    }

    /// Marks a public key as being used. Returns true if a key was found and set to used.
    fn mark_public_key_as_used(
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

    fn mark_public_key_hash_as_used(
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

    /// Marks a vrf public key as being used. Returns true if a key was found and set to used.
    fn mark_vrf_public_key_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key: &VRFPublicKey,
    ) -> KeyChainResult<bool> {
        let lookahead_size = self.lookahead_size();
        if self.vrf_chain.mark_pubkey_as_used(db_tx, public_key, lookahead_size)? {
            return Ok(true);
        }
        Ok(false)
    }

    fn get_multisig_challenge(
        &self,
        destination: &Destination,
    ) -> Option<&ClassicMultisigChallenge> {
        self.standalone_multisig_keys
            .get(destination)
            .map(|multisig| &multisig.challenge)
    }

    /// Add, rename or delete a label for a standalone address not from the keys derived from this account
    fn standalone_address_label_rename(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        new_address: Destination,
        new_label: Option<String>,
    ) -> KeyChainResult<()> {
        if let Some(watch_only) = self.standalone_watch_only_keys.get(&new_address) {
            let key = watch_only.with_new_label(new_label);

            let id = AccountPrefixedId::new(self.get_account_id(), new_address);
            db_tx.set_standalone_watch_only_key(&id, &key)?;
            self.standalone_watch_only_keys.insert(id.into_item_id(), key);
            Ok(())
        } else if let Some(multisig) = self.standalone_multisig_keys.get(&new_address) {
            let key = multisig.with_new_label(new_label);

            let id = AccountPrefixedId::new(self.get_account_id(), new_address);
            db_tx.set_standalone_multisig_key(&id, &key)?;
            self.standalone_multisig_keys.insert(id.into_item_id(), key);
            Ok(())
        } else {
            let addr = RpcAddress::new(&self.chain_config, new_address)?;
            Err(KeyChainError::NoStandaloneAddressFound(addr))
        }
    }

    /// Adds a new public key hash to be watched, standalone from the keys derived from this account
    fn add_standalone_watch_only_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        new_address: PublicKeyHash,
        label: Option<String>,
    ) -> KeyChainResult<()> {
        let destination = Destination::PublicKeyHash(new_address);
        if self.standalone_watch_only_keys.contains_key(&destination) {
            let addr = RpcAddress::new(&self.chain_config, destination)?;
            return Err(KeyChainError::StandaloneAddressAlreadyExists(addr));
        }

        let id = AccountPrefixedId::new(self.get_account_id(), destination);
        let key = StandaloneWatchOnlyKey { label };

        db_tx.set_standalone_watch_only_key(&id, &key)?;
        self.standalone_watch_only_keys.insert(id.into_item_id(), key);

        Ok(())
    }

    ///  Adds a new private key to be watched, standalone from the keys derived from this account
    fn add_standalone_private_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        new_private_key: PrivateKey,
        label: Option<String>,
    ) -> KeyChainResult<()> {
        let public_key = PublicKey::from_private_key(&new_private_key);
        let destination = Destination::PublicKey(public_key.clone());
        if self.standalone_private_keys.contains_key(&destination) {
            let addr = RpcAddress::new(&self.chain_config, destination)?;
            return Err(KeyChainError::StandaloneAddressAlreadyExists(addr));
        }

        let public_key_hash = PublicKeyHash::from(&public_key);
        let id = AccountPrefixedId::new(self.get_account_id(), public_key);

        db_tx.set_standalone_private_key(&id, &new_private_key, label.clone())?;
        self.standalone_private_keys.insert(destination, (label.clone(), id.clone()));
        self.standalone_private_keys
            .insert(Destination::PublicKeyHash(public_key_hash), (label, id));

        Ok(())
    }

    /// Adds a multisig to be watched
    fn add_standalone_multisig(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        challenge: ClassicMultisigChallenge,
        label: Option<String>,
    ) -> KeyChainResult<PublicKeyHash> {
        let multisig_pkh: PublicKeyHash = (&challenge).into();
        let destination = Destination::ClassicMultisig(multisig_pkh);
        if self.standalone_multisig_keys.contains_key(&destination) {
            let addr = RpcAddress::new(&self.chain_config, destination)?;
            return Err(KeyChainError::StandaloneAddressAlreadyExists(addr));
        }

        let id = AccountPrefixedId::new(self.get_account_id(), destination);
        let key = StandaloneMultisig { label, challenge };

        db_tx.set_standalone_multisig_key(&id, &key)?;
        self.standalone_multisig_keys.insert(id.into_item_id(), key);

        Ok(multisig_pkh)
    }

    fn get_all_issued_addresses(
        &self,
        key_purpose: KeyPurpose,
    ) -> BTreeMap<ChildNumber, Address<Destination>> {
        self.get_leaf_key_chain(key_purpose).get_all_issued_addresses()
    }

    fn get_all_standalone_addresses(&self) -> StandaloneAddresses {
        StandaloneAddresses {
            watch_only_addresses: self.standalone_watch_only_keys.clone().into_iter().collect(),
            multisig_addresses: self.standalone_multisig_keys.clone().into_iter().collect(),
            private_keys: self
                .standalone_private_keys
                .iter()
                .filter_map(|(dest, (label, _))| match dest {
                    Destination::PublicKey(pk) => Some((pk.clone(), label.clone())),
                    Destination::PublicKeyHash(_)
                    | Destination::AnyoneCanSpend
                    | Destination::ScriptHash(_)
                    | Destination::ClassicMultisig(_) => None,
                })
                .collect(),
        }
    }

    fn get_all_standalone_address_details(
        &self,
        address: Destination,
    ) -> Option<(Destination, StandaloneAddressDetails)> {
        if let Some(details) = self.standalone_multisig_keys.get(&address).cloned() {
            Some((address, StandaloneAddressDetails::Multisig(details)))
        } else if let Some((label, _)) = self.standalone_private_keys.get(&address) {
            Some((address, StandaloneAddressDetails::PrivateKey(label.clone())))
        } else {
            self.standalone_watch_only_keys
                .get(&address)
                .cloned()
                .map(|details| (address, StandaloneAddressDetails::WatchOnly(details)))
        }
    }

    fn get_addresses_usage_state(&self, key_purpose: KeyPurpose) -> &KeychainUsageState {
        self.get_leaf_key_chain(key_purpose).usage_state()
    }
}

impl VRFAccountKeyChains for AccountKeyChainImpl<VrfKeySoftChain> {
    /// Issue a new derived vrf key that hasn't been used before
    fn issue_vrf_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> KeyChainResult<(ChildNumber, ExtendedVRFPublicKey)> {
        let lookahead_size = self.lookahead_size();
        self.vrf_chain.issue_new(db_tx, lookahead_size)
    }

    fn get_vrf_private_key_for_public_key(
        &self,
        public_key: &VRFPublicKey,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<Option<ExtendedVRFPrivateKey>> {
        let xpriv = self.derive_account_private_vrf_key(db_tx)?;

        if let Some(xpub) = self.vrf_chain.get_derived_xpub_from_public_key(public_key) {
            return Self::get_vrf_private_key(&xpriv, xpub).map(Option::Some);
        }
        Ok(None)
    }

    fn get_all_issued_vrf_public_keys(
        &self,
    ) -> BTreeMap<ChildNumber, (Address<VRFPublicKey>, bool)> {
        self.vrf_chain.get_all_issued_keys()
    }

    fn get_legacy_vrf_public_key(&self) -> Address<VRFPublicKey> {
        self.vrf_chain.get_legacy_vrf_public_key()
    }

    fn get_private_key_for_destination(
        &self,
        destination: &Destination,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<Option<PrivateKey>> {
        let xpriv = self.derive_account_private_key(db_tx)?;
        for purpose in KeyPurpose::ALL {
            let leaf_key = self.get_leaf_key_chain(purpose);
            if let Some(xpub) = leaf_key
                .get_child_num_from_destination(destination)
                .and_then(|child_num| leaf_key.get_derived_xpub(child_num))
            {
                return Self::get_private_key(&xpriv, xpub).map(|pk| Some(pk.private_key()));
            }
        }

        let standalone_pk = self
            .standalone_private_keys
            .get(destination)
            .map(|(_, acc_public_key)| db_tx.get_account_standalone_private_key(acc_public_key))
            .transpose()?
            .flatten();

        Ok(standalone_pk)
    }
}

#[cfg(test)]
mod tests;

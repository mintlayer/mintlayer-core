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

use crate::key_chain::with_purpose::WithPurpose;
use crate::key_chain::{get_purpose_and_index, KeyChainError, KeyChainResult};
use common::address::pubkeyhash::PublicKeyHash;
use common::address::Address;
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::ExtendedPublicKey;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::hdkd::u31::U31;
use crypto::key::PublicKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use utils::const_value::ConstValue;
use utils::ensure;
use wallet_storage::{WalletStorageReadLocked, WalletStorageWriteLocked};
use wallet_types::keys::{KeyPurpose, KeychainUsageState};
use wallet_types::{AccountDerivationPathId, AccountId, AccountKeyPurposeId};

// TODO: Switch to the hard derivation because it's more secure

/// A child key hierarchy for an AccountKeyChain. This normally implements the receiving and change
/// addresses key chains. It uses soft derivation to generate addresses (xpub).
pub struct LeafKeySoftChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The account id this leaf key chain belongs to
    account_id: AccountId,

    /// The purpose of this leaf key chain
    purpose: KeyPurpose,

    /// The parent key of this key chain
    parent_pubkey: ConstValue<ExtendedPublicKey>,

    // TODO: many of these members (the BTreeMaps) are highly coupled and are used in certain ways in tandem.
    //       See if we can move them into submodules that are individually testable
    // TODO: We should probably update ChildNumber key to U31 all these maps.
    /// The derived addresses for the receiving funds or change. Those are derived as needed.
    addresses: BTreeMap<ChildNumber, Address<Destination>>,

    /// The derived keys for the receiving funds or change. Those are derived as needed.
    derived_public_keys: BTreeMap<ChildNumber, ExtendedPublicKey>,

    /// All the public key that this key chain holds
    public_key_to_index: BTreeMap<PublicKey, ChildNumber>,

    /// All the public key hashes that this key chain holds
    public_key_hash_to_index: BTreeMap<PublicKeyHash, ChildNumber>,

    /// The usage state of this key chain
    usage_state: KeychainUsageState,
}

impl LeafKeySoftChain {
    pub fn new_empty(
        chain_config: Arc<ChainConfig>,
        account_id: AccountId,
        purpose: KeyPurpose,
        parent_pubkey: ExtendedPublicKey,
    ) -> Self {
        Self {
            chain_config,
            account_id,
            purpose,
            parent_pubkey: parent_pubkey.into(),
            addresses: BTreeMap::new(),
            derived_public_keys: BTreeMap::new(),
            public_key_to_index: BTreeMap::new(),
            public_key_hash_to_index: BTreeMap::new(),
            usage_state: KeychainUsageState::default(),
        }
    }

    // TODO reduce the number of parameters
    #[allow(clippy::too_many_arguments)]
    fn new_from_parts(
        chain_config: Arc<ChainConfig>,
        account_id: AccountId,
        purpose: KeyPurpose,
        parent_pubkey: ExtendedPublicKey,
        addresses: BTreeMap<ChildNumber, Address<Destination>>,
        derived_public_keys: BTreeMap<ChildNumber, ExtendedPublicKey>,
        usage_state: KeychainUsageState,
    ) -> KeyChainResult<Self> {
        // TODO optimize for database structure
        let public_keys_to_index: BTreeMap<PublicKey, ChildNumber> = derived_public_keys
            .iter()
            .map(|(idx, xpub)| (xpub.clone().into_public_key(), *idx))
            .collect();
        let public_key_hashes_to_index: BTreeMap<PublicKeyHash, ChildNumber> = public_keys_to_index
            .iter()
            .map(|(pk, idx)| (PublicKeyHash::from(pk), *idx))
            .collect();

        Ok(Self {
            chain_config,
            account_id,
            purpose,
            parent_pubkey: parent_pubkey.into(),
            addresses,
            derived_public_keys,
            public_key_to_index: public_keys_to_index,
            public_key_hash_to_index: public_key_hashes_to_index,
            usage_state,
        })
    }

    pub fn load_leaf_keys(
        chain_config: Arc<ChainConfig>,
        account_pubkey: &ExtendedPublicKey,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
    ) -> KeyChainResult<WithPurpose<LeafKeySoftChain>> {
        let mut addresses = WithPurpose::new(BTreeMap::new(), BTreeMap::new());
        for (address_id, address) in db_tx.get_addresses(id)? {
            let address =
                Address::<Destination>::from_string(chain_config.as_ref(), address.as_str())?;
            let (purpose, key_index) = get_purpose_and_index(&address_id.into_item_id())?;
            let old_value = addresses.mut_for(purpose).insert(key_index, address);
            if old_value.is_some() {
                return Err(KeyChainError::CouldNotLoadKeyChain);
            }
        }

        let mut public_keys = WithPurpose::new(BTreeMap::new(), BTreeMap::new());
        for (pubkey_id, xpub) in db_tx.get_public_keys(id)? {
            let (purpose, key_index) = get_purpose_and_index(&pubkey_id.into_item_id())?;
            let old_value = public_keys.mut_for(purpose).insert(key_index, xpub);
            if old_value.is_some() {
                return Err(KeyChainError::CouldNotLoadKeyChain);
            }
        }

        // TODO make db_tx.get_keychain_usage_states return a Map<KeyPurpose, ...>
        let mut usage_states: BTreeMap<KeyPurpose, KeychainUsageState> = db_tx
            .get_keychain_usage_states(id)?
            .into_iter()
            .map(|(k, v)| (k.into_item_id(), v))
            .collect();

        Ok(WithPurpose::new(
            LeafKeySoftChain::new_from_parts(
                chain_config.clone(),
                id.clone(),
                KeyPurpose::ReceiveFunds,
                account_pubkey
                    .clone()
                    .derive_child(KeyPurpose::ReceiveFunds.get_deterministic_index())?,
                addresses.receive,
                public_keys.receive,
                usage_states.remove(&KeyPurpose::ReceiveFunds).ok_or(
                    KeyChainError::MissingDatabaseProperty("ReceiveFunds usage state"),
                )?,
            )?,
            LeafKeySoftChain::new_from_parts(
                chain_config,
                id.clone(),
                KeyPurpose::Change,
                account_pubkey
                    .clone()
                    .derive_child(KeyPurpose::Change.get_deterministic_index())?,
                addresses.change,
                public_keys.change,
                usage_states
                    .remove(&KeyPurpose::Change)
                    .ok_or(KeyChainError::MissingDatabaseProperty("Change usage state"))?,
            )?,
        ))
    }

    /// Return the next unused key, this will reuse any already issued but not used keys,
    /// or issue a new one if all issued keys are already used
    pub fn next_unused(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> KeyChainResult<(ChildNumber, ExtendedPublicKey, Address<Destination>)> {
        let new_issued_index = {
            match self.last_used() {
                None => U31::ZERO,
                Some(last_used) => last_used.plus_one()?,
            }
        };

        let key = self.derive_and_add_key(db_tx, new_issued_index)?;

        let index = ChildNumber::from_normal(new_issued_index);

        let address = self.addresses.get(&index).expect("The address should be derived").clone();

        if self.last_used() == self.last_issued() {
            logging::log::debug!(
                "new address: {}, index: {}, purpose {:?}",
                address.as_str(),
                new_issued_index,
                self.purpose
            );

            self.usage_state.increment_up_to_last_issued(new_issued_index);
            self.save_usage_state(db_tx)?;
        }

        Ok((index, key, address))
    }

    /// Issue a new key
    pub fn issue_new(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        lookahead_size: u32,
    ) -> KeyChainResult<(ChildNumber, ExtendedPublicKey, Address<Destination>)> {
        let new_issued_index = self.get_new_issued_index(lookahead_size)?;

        let key = self.derive_and_add_key(db_tx, new_issued_index)?;

        let index = ChildNumber::from_normal(new_issued_index);

        let address = self.addresses.get(&index).expect("The address should be derived").clone();

        logging::log::debug!(
            "new address: {}, index: {}, purpose {:?}",
            address.as_str(),
            new_issued_index,
            self.purpose
        );

        self.usage_state.increment_up_to_last_issued(new_issued_index);
        self.save_usage_state(db_tx)?;

        Ok((index, key, address))
    }

    /// Persist the usage state to the database
    pub fn save_usage_state(
        &self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> KeyChainResult<()> {
        db_tx
            .set_keychain_usage_state(
                &AccountKeyPurposeId::new(self.account_id.clone(), self.purpose),
                &self.usage_state,
            )
            .map_err(KeyChainError::DatabaseError)
    }

    /// Get a new issued index and check that it is a valid one i.e. not exceeding the lookahead
    fn get_new_issued_index(&self, lookahead_size: u32) -> KeyChainResult<U31> {
        let new_issued_index = {
            match self.last_issued() {
                None => U31::ZERO,
                Some(last_issued) => last_issued.plus_one()?,
            }
        };

        // Check if we can issue a key
        self.check_issued_lookahead(new_issued_index, lookahead_size)?;
        Ok(new_issued_index)
    }

    /// Check if a new key can be issued with the provided index
    fn check_issued_lookahead(
        &self,
        new_index_to_issue: U31,
        lookahead_size: u32,
    ) -> KeyChainResult<()> {
        // Check if the issued addresses are less or equal to lookahead size
        let lookahead_exceeded = match self.last_used() {
            None => new_index_to_issue.into_u32() >= lookahead_size,
            Some(last_used_index) => {
                new_index_to_issue.into_u32() > last_used_index.into_u32() + lookahead_size
            }
        };

        ensure!(!lookahead_exceeded, KeyChainError::LookAheadExceeded);

        Ok(())
    }

    /// Derives a key or gets it from the precomputed key pool.
    fn derive_key(&self, key_index: U31) -> KeyChainResult<ExtendedPublicKey> {
        // Get the public key from the key pool if available
        if let Some(pub_key) = self.derived_public_keys.get(&ChildNumber::from_normal(key_index)) {
            return Ok(pub_key.clone());
        }

        // Derive the key
        Ok(self
            .parent_pubkey
            .clone()
            .take()
            .derive_child(ChildNumber::from_normal(key_index))?)
    }

    /// Derives and adds a key to this key chain. This does not affect the last used and issued state
    fn derive_and_add_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        key_index: U31,
    ) -> KeyChainResult<ExtendedPublicKey> {
        // Get the public key from the key pool if available
        if let Some(pub_key) = self.derived_public_keys.get(&ChildNumber::from_normal(key_index)) {
            return Ok(pub_key.clone());
        }

        // Derive the new extended public key
        let derived_key = self.derive_key(key_index)?;
        // Just the public key
        let public_key = derived_key.clone().into_public_key();
        // Calculate public key hash
        let public_key_hash = PublicKeyHash::from(&public_key);
        // Calculate the address
        let address = Address::new(
            &self.chain_config,
            Destination::PublicKeyHash(public_key_hash),
        )?;
        // Calculate account derivation path id
        let account_path_id = AccountDerivationPathId::new(
            self.account_id.clone(),
            derived_key.get_derivation_path().clone(),
        );

        // Save issued key and address
        db_tx.set_public_key(&account_path_id, &derived_key)?;
        db_tx.set_address(&account_path_id, &address)?;

        // Add key and address to the maps
        self.derived_public_keys
            .insert(ChildNumber::from_normal(key_index), derived_key.clone());
        self.addresses.insert(ChildNumber::from_normal(key_index), address);
        self.public_key_to_index.insert(public_key, ChildNumber::from_normal(key_index));
        self.public_key_hash_to_index
            .insert(public_key_hash, ChildNumber::from_normal(key_index));

        Ok(derived_key)
    }

    /// Get the last derived key index
    pub fn get_last_derived_index(&self) -> Option<ChildNumber> {
        self.derived_public_keys.keys().last().copied()
    }

    /// Derive up `lookahead_size` keys starting from the last used index. If the gap from the last
    /// used key to the last derived key is already `lookahead_size`, this method has no effect
    pub fn top_up(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        lookahead_size: u32,
    ) -> KeyChainResult<()> {
        // Find how many keys to derive
        let starting_index = match self.get_last_derived_index() {
            None => 0,
            Some(last_derived_index) => last_derived_index.get_index().into_u32() + 1,
        };

        let up_to_index = match self.last_used() {
            None => lookahead_size,
            Some(last_used) => last_used.into_u32() + lookahead_size + 1,
        };

        // Derive the needed keys (the loop can be )
        for i in starting_index..up_to_index {
            if let Some(index) = U31::from_u32(i) {
                self.derive_and_add_key(db_tx, index)?;
            }
        }

        Ok(())
    }

    pub fn is_destination_mine(&self, dest: &Destination) -> bool {
        match dest {
            Destination::PublicKeyHash(pkh) => self.is_public_key_hash_mine(pkh),
            Destination::PublicKey(pk) => self.is_public_key_mine(pk),
            Destination::AnyoneCanSpend
            | Destination::ScriptHash(_)
            | Destination::ClassicMultisig(_) => false, // TODO: This can also have another public key hash function
        }
    }

    pub fn is_public_key_mine(&self, public_key: &PublicKey) -> bool {
        self.public_key_to_index.contains_key(public_key)
    }

    pub fn is_public_key_hash_mine(&self, pubkey_hash: &PublicKeyHash) -> bool {
        self.public_key_hash_to_index.contains_key(pubkey_hash)
    }

    /// Get the extended public key provided a destination or None if no key found
    pub fn get_child_num_from_destination(&self, dest: &Destination) -> Option<ChildNumber> {
        match dest {
            Destination::PublicKeyHash(pkh) => self.get_child_num_from_public_key_hash(pkh),
            Destination::PublicKey(pk) => self.get_child_num_from_public_key(pk),
            Destination::AnyoneCanSpend
            | Destination::ScriptHash(_)
            | Destination::ClassicMultisig(_) => None,
        }
    }

    pub fn get_derived_xpub(&self, child_num: ChildNumber) -> Option<&ExtendedPublicKey> {
        self.derived_public_keys.get(&child_num)
    }

    /// Get the extended public key provided a public key or None if no key found
    pub fn get_child_num_from_public_key(&self, pub_key: &PublicKey) -> Option<ChildNumber> {
        self.public_key_to_index.get(pub_key).copied()
    }

    /// Get the extended public key provided a public key hash or None if no key found
    pub fn get_child_num_from_public_key_hash(&self, pkh: &PublicKeyHash) -> Option<ChildNumber> {
        self.public_key_hash_to_index.get(pkh).copied()
    }

    /// Get public key for public key hash or None if no key found
    pub fn get_public_key_from_public_key_hash(&self, pkh: &PublicKeyHash) -> Option<PublicKey> {
        let child_number = self.public_key_hash_to_index.get(pkh)?;
        self.derived_public_keys
            .get(child_number)
            .map(|pk| pk.clone().into_public_key())
    }

    /// Mark a specific key as used in the key pool. This will update the last used key index if
    /// necessary. Returns false if a key was found and set to used.
    fn mark_child_key_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        child_num: ChildNumber,
        lookahead_size: u32,
    ) -> KeyChainResult<()> {
        self.usage_state.increment_up_to_last_used(child_num.get_index());
        self.save_usage_state(db_tx)?;
        self.top_up(db_tx, lookahead_size)
    }

    pub fn mark_pubkey_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key: &PublicKey,
        lookahead_size: u32,
    ) -> KeyChainResult<bool> {
        if let Some(child_num) = self.get_child_num_from_public_key(public_key) {
            self.mark_child_key_as_used(db_tx, child_num, lookahead_size)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn mark_pub_key_hash_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key_hash: &PublicKeyHash,
        lookahead_size: u32,
    ) -> KeyChainResult<bool> {
        if let Some(child_num) = self.get_child_num_from_public_key_hash(public_key_hash) {
            self.mark_child_key_as_used(db_tx, child_num, lookahead_size)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the index of the last used key or None if no key is used
    pub fn last_used(&self) -> Option<U31> {
        self.usage_state.last_used()
    }

    /// Get the index of the last issued key or None if no key is issued
    pub fn last_issued(&self) -> Option<U31> {
        self.usage_state.last_issued()
    }

    pub fn get_all_issued_addresses(&self) -> BTreeMap<ChildNumber, Address<Destination>> {
        let last_issued = match self.usage_state.last_issued() {
            Some(index) => index,
            None => return BTreeMap::new(),
        };

        let last_issued = ChildNumber::from_normal(last_issued);

        self.addresses
            .clone()
            .into_iter()
            .filter(|(index, _address)| *index <= last_issued)
            .collect()
    }

    pub fn usage_state(&self) -> &KeychainUsageState {
        &self.usage_state
    }
}

// TODO: tests

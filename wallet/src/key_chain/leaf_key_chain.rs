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

use crate::key_chain::{get_purpose_and_index, KeyChainError, KeyChainResult};
use common::address::pubkeyhash::PublicKeyHash;
use common::address::Address;
use common::chain::ChainConfig;
use crypto::key::extended::ExtendedPublicKey;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::PublicKey;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::sync::Arc;
use storage::Backend;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::keys::{KeyPurpose, KeychainUsageState};
use wallet_types::{
    AccountDerivationPathId, AccountId, AccountKeyPurposeId, DeterministicAccountInfo,
};

/// A child key hierarchy for an AccountKeyChain. This normally implements the receiving and change
/// addresses key chains
#[allow(dead_code)] // TODO remove
pub struct LeafKeyChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The account id this leaf key chain belongs to
    account_id: AccountId,

    /// The purpose of this leaf key chain
    purpose: KeyPurpose,

    /// The parent key of this key chain
    parent_pubkey: ExtendedPublicKey,

    /// The derived addresses for the receiving funds or change. Those are derived as needed.
    addresses: BTreeMap<ChildNumber, Address>,

    /// The derived keys for the receiving funds or change. Those are derived as needed.
    derived_public_keys: BTreeMap<ChildNumber, ExtendedPublicKey>,

    /// All the public key that this key chain holds
    public_keys: BTreeSet<PublicKey>,

    /// All the public key hashes that this key chain holds
    public_key_hashes: BTreeSet<PublicKeyHash>,

    /// The usage state of this key chain
    usage_state: KeychainUsageState,

    /// A copy of the lookahead size of the account
    lookahead_size: u32,
}

impl LeafKeyChain {
    pub fn new_empty(
        chain_config: Arc<ChainConfig>,
        account_id: AccountId,
        purpose: KeyPurpose,
        parent_pubkey: ExtendedPublicKey,
        lookahead_size: u32,
    ) -> Self {
        Self {
            chain_config,
            account_id,
            purpose,
            parent_pubkey,
            addresses: BTreeMap::new(),
            derived_public_keys: BTreeMap::new(),
            public_keys: BTreeSet::new(),
            public_key_hashes: BTreeSet::new(),
            usage_state: KeychainUsageState::default(),
            lookahead_size,
        }
    }

    // TODO reduce the number of parameters
    #[allow(clippy::too_many_arguments)]
    fn new_from_parts(
        chain_config: Arc<ChainConfig>,
        account_id: AccountId,
        purpose: KeyPurpose,
        parent_pubkey: ExtendedPublicKey,
        addresses: BTreeMap<ChildNumber, Address>,
        derived_public_keys: BTreeMap<ChildNumber, ExtendedPublicKey>,
        usage_state: KeychainUsageState,
        lookahead_size: u32,
    ) -> KeyChainResult<Self> {
        // TODO optimize for database structure
        let mut public_key_hashes = BTreeSet::new();
        for address in addresses.values() {
            let pkh = PublicKeyHash::try_from(address.data(&chain_config)?)?;
            public_key_hashes.insert(pkh);
        }

        let mut public_keys = BTreeSet::new();
        for xpub in derived_public_keys.values() {
            public_keys.insert(xpub.clone().into_public_key());
        }

        Ok(Self {
            chain_config,
            account_id,
            purpose,
            parent_pubkey,
            addresses,
            derived_public_keys,
            public_keys,
            public_key_hashes,
            usage_state,
            lookahead_size,
        })
    }

    pub fn load_leaf_keys<B: Backend>(
        chain_config: Arc<ChainConfig>,
        account_info: &DeterministicAccountInfo,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> KeyChainResult<(LeafKeyChain, LeafKeyChain)> {
        let mut receiving_addresses = BTreeMap::new();
        let mut change_addresses = BTreeMap::new();

        for (address_id, address) in db_tx.get_addresses(id)? {
            let (purpose, key_index) = get_purpose_and_index(&address_id.into_item_id())?;
            let old_value = match purpose {
                KeyPurpose::ReceiveFunds => receiving_addresses.insert(key_index, address),
                KeyPurpose::Change => change_addresses.insert(key_index, address),
            };
            if old_value.is_some() {
                return Err(KeyChainError::CouldNotLoadKeyChain);
            }
        }

        let mut receiving_public_keys = BTreeMap::new();
        let mut change_public_keys = BTreeMap::new();
        for (pubkey_id, xpub) in db_tx.get_public_keys(id)? {
            let (purpose, key_index) = get_purpose_and_index(&pubkey_id.into_item_id())?;
            let old_value = match purpose {
                KeyPurpose::ReceiveFunds => receiving_public_keys.insert(key_index, xpub),
                KeyPurpose::Change => change_public_keys.insert(key_index, xpub),
            };
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

        let account_pubkey = account_info.get_account_key();

        Ok((
            LeafKeyChain::new_from_parts(
                chain_config.clone(),
                id.clone(),
                KeyPurpose::ReceiveFunds,
                account_pubkey
                    .clone()
                    .derive_child(KeyPurpose::ReceiveFunds.get_deterministic_index())?,
                receiving_addresses,
                receiving_public_keys,
                usage_states.remove(&KeyPurpose::ReceiveFunds).ok_or(
                    KeyChainError::MissingDatabaseProperty("ReceiveFunds usage state"),
                )?,
                account_info.get_lookahead_size(),
            )?,
            LeafKeyChain::new_from_parts(
                chain_config,
                id.clone(),
                KeyPurpose::Change,
                account_pubkey
                    .clone()
                    .derive_child(KeyPurpose::Change.get_deterministic_index())?,
                change_addresses,
                change_public_keys,
                usage_states
                    .remove(&KeyPurpose::Change)
                    .ok_or(KeyChainError::MissingDatabaseProperty("Change usage state"))?,
                account_info.get_lookahead_size(),
            )?,
        ))
    }

    pub fn issue_address<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
    ) -> KeyChainResult<Address> {
        let new_issued_index = self.get_new_issued_index()?;

        // Get address or derive one if necessary
        let issued_address = match self.addresses.get(&new_issued_index) {
            Some(address) => address.clone(),
            None => {
                self.derive_and_add_key(db_tx, new_issued_index)?;
                self.addresses
                    .get(&new_issued_index)
                    .expect("The address should be derived")
                    .clone()
            }
        };

        self.set_key_index_as_issued(db_tx, new_issued_index)?;

        Ok(issued_address)
    }

    /// Issue a new key. This does not check if lookahead margins are observed
    pub fn issue_key<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
    ) -> KeyChainResult<ExtendedPublicKey> {
        let new_issued_index = self.get_new_issued_index()?;

        // Get key or derive one if necessary
        let issued_key = match self.derived_public_keys.get(&new_issued_index) {
            Some(key) => key.clone(),
            None => self.derive_and_add_key(db_tx, new_issued_index)?,
        };

        self.set_key_index_as_issued(db_tx, new_issued_index)?;

        Ok(issued_key)
    }

    /// Set a specific key index as used
    fn set_key_index_as_issued<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        new_issued_index: ChildNumber,
    ) -> KeyChainResult<()> {
        // Save usage state
        self.usage_state.set_last_issued(Some(new_issued_index));
        self.save_usage_state(db_tx)
    }

    /// Persist the usage state to the database
    pub fn save_usage_state<B: Backend>(&self, db_tx: &mut StoreTxRw<B>) -> KeyChainResult<()> {
        Ok(db_tx.set_keychain_usage_state(
            &AccountKeyPurposeId::new(self.account_id.clone(), self.purpose),
            &self.usage_state,
        )?)
    }

    /// Get a new issued index and check that it is a valid one i.e. not exceeding the lookahead
    fn get_new_issued_index(&self) -> KeyChainResult<ChildNumber> {
        // TODO consider last used index as well
        let new_issued_index = {
            match self.usage_state.get_last_issued() {
                None => ChildNumber::ZERO,
                Some(last_issued) => last_issued.increment()?,
            }
        };

        // Check if we can issue a key
        self.check_issued_lookahead(new_issued_index)?;
        Ok(new_issued_index)
    }

    /// Check if a new key can be issued with the provided index
    fn check_issued_lookahead(&self, new_index_to_issue: ChildNumber) -> KeyChainResult<()> {
        let usage_state = &self.usage_state;

        let new_issued_index = new_index_to_issue.get_index();

        // Check if the issued addresses are less or equal to lookahead size
        let lookahead_exceeded = match usage_state.get_last_used() {
            None => new_issued_index >= self.lookahead_size,
            Some(last_used_index) => {
                new_issued_index > last_used_index.get_index() + self.lookahead_size
            }
        };

        if lookahead_exceeded {
            Err(KeyChainError::LookAheadExceeded)
        } else {
            Ok(())
        }
    }

    /// Derives a key or gets it from the precomputed key pool.
    fn derive_key(&self, key_index: ChildNumber) -> KeyChainResult<ExtendedPublicKey> {
        // Get the public key from the key pool if available
        if let Some(pub_key) = self.derived_public_keys.get(&key_index) {
            return Ok(pub_key.clone());
        }

        // Create the new key path
        let key_path = {
            let mut path = self.parent_pubkey.get_derivation_path().clone().into_vec();
            path.push(key_index);
            path.try_into()?
        };

        // Derive the key
        Ok(self.parent_pubkey.clone().derive_absolute_path(&key_path)?)
    }

    /// Derives and adds a key to his key chain. This does not affect the last used and issued state
    fn derive_and_add_key<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        key_index: ChildNumber,
    ) -> KeyChainResult<ExtendedPublicKey> {
        // Get the public key from the key pool if available
        if let Some(pub_key) = self.derived_public_keys.get(&key_index) {
            return Ok(pub_key.clone());
        }

        // Derive the new extended public key
        let derived_key = self.derive_key(key_index)?;
        // Just the public key
        let public_key = derived_key.clone().into_public_key();
        // Calculate public key hash
        let public_key_hash = PublicKeyHash::from(&public_key);
        // Calculate the address
        let address = Address::from_public_key_hash(&self.chain_config, &public_key_hash)?;
        // Calculate account derivation path id
        let account_path_id = AccountDerivationPathId::new(
            self.account_id.clone(),
            derived_key.get_derivation_path().clone(),
        );

        // Save issued key and address
        db_tx.set_public_key(&account_path_id, &derived_key)?;
        db_tx.set_address(&account_path_id, &address)?;

        // Add key and address the maps
        self.derived_public_keys.insert(key_index, derived_key.clone());
        self.addresses.insert(key_index, address);
        self.public_keys.insert(public_key);
        self.public_key_hashes.insert(public_key_hash);

        Ok(derived_key)
    }

    /// Get the last derived key index
    pub fn get_last_derived_index(&self) -> Option<ChildNumber> {
        self.derived_public_keys.last_key_value().map(|(k, _)| *k)
    }

    /// Derive up `lookahead_size` keys starting from the last used index. If the gap from the last
    /// used key to the last derived key is already `lookahead_size`, this method has no effect
    pub fn top_up<B: Backend>(&mut self, db_tx: &mut StoreTxRw<B>) -> KeyChainResult<()> {
        // Find how many keys to derive
        let (starting_index, up_to_index) = match self.get_last_derived_index() {
            None => (0u32, self.lookahead_size),
            Some(last_derived_index) => {
                let start_index = last_derived_index.increment()?.get_index();
                let up_to_index = match self.usage_state.get_last_used() {
                    None => self.lookahead_size,
                    Some(last_used) => last_used.get_index() + self.lookahead_size + 1,
                };
                (start_index, up_to_index)
            }
        };

        // If there are any keys that need to be derived
        if starting_index < up_to_index {
            // Derive the needed keys
            for i in starting_index..up_to_index {
                let index = ChildNumber::from_index_with_hardened_bit(i);
                self.derive_and_add_key(db_tx, index)?;
            }
        }

        Ok(())
    }

    /// Set the copy of `lookahead_size` of this leaf keychain. This shouldn't be used directly
    pub fn set_lookahead_size(&mut self, lookahead_size: u32) {
        self.lookahead_size = lookahead_size;
    }

    /// Return true if `public_key` belongs to this key chain's derived pool. If the key can be
    /// derived from the `parent_pubkey` but is not in the key pool, then this will return false,
    /// use the `LeafKeyChain::is_pubkey_mine` instead to check membership.
    pub fn is_pubkey_mine_in_key_pool(&self, public_key: &ExtendedPublicKey) -> bool {
        self.is_pubkey_mine(public_key, false)
    }

    /// Return true if `public_key` belongs to this key chain. Set `derive_if_necessary` to true
    /// for checking membership by deriving the key if necessary.
    pub fn is_pubkey_mine(
        &self,
        public_key: &ExtendedPublicKey,
        derive_if_necessary: bool,
    ) -> bool {
        // The public_key derivation path must be longer than the parent of this key chain
        if let Some(path_diff) = public_key
            .get_derivation_path()
            .get_super_path_diff(self.parent_pubkey.get_derivation_path())
        {
            // The path difference must be 1 i.e. the key index
            if path_diff.len() == 1 {
                let key_index = path_diff[0];
                // Check if we expect this key to be derived
                let is_pub_key_derived = match self.get_last_derived_index() {
                    None => false,
                    Some(last_derived_index) => {
                        key_index.get_index() <= last_derived_index.get_index()
                    }
                };

                if is_pub_key_derived {
                    if let Some(pk) = self.derived_public_keys.get(&key_index) {
                        return pk == public_key;
                    }
                } else if derive_if_necessary {
                    if let Ok(pk) = &self.derive_key(key_index) {
                        return pk == public_key;
                    }
                }
            }
        }
        false
    }

    pub fn is_public_key_mine(&self, public_key: &PublicKey) -> bool {
        self.public_keys.contains(public_key)
    }

    pub fn is_public_key_hash_mine(&self, pubkey_hash: &PublicKeyHash) -> bool {
        self.public_key_hashes.contains(pubkey_hash)
    }

    /// Mark a specific key as used in the key pool. This will update the last used key index if
    /// necessary. Returns false if a key was found and set to used.
    pub fn mark_key_pool_pubkey_as_used<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        public_key: &ExtendedPublicKey,
    ) -> KeyChainResult<bool> {
        // Check if public key is in the key pool
        if self.is_pubkey_mine_in_key_pool(public_key) {
            // Get the key index of the public key, this should always be Some
            let key_index = public_key.get_derivation_path().as_slice().last()
                .expect("The provided public key belongs to this key chain, hence it should always have a key index");
            self.usage_state.set_last_used(Some(*key_index));
            db_tx.set_keychain_usage_state(
                &AccountKeyPurposeId::new(self.account_id.clone(), self.purpose),
                &self.usage_state,
            )?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Get the index of the last used key or None if no key is used
    #[allow(dead_code)] // TODO remove
    pub fn get_last_used(&self) -> Option<ChildNumber> {
        self.usage_state.get_last_used()
    }

    /// Get the index of the last issued key or None if no key is issued
    #[allow(dead_code)] // TODO remove
    pub fn get_last_issued(&self) -> Option<ChildNumber> {
        self.usage_state.get_last_issued()
    }

    pub fn usage_state(&self) -> &KeychainUsageState {
        &self.usage_state
    }
}

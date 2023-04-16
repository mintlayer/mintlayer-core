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

//! # BIP39 key chain
//! The KeyChain struct holds and constantly derives keys for the wallet addresses
//! It uses the following derivation scheme:
//!
//! m/44'/19788'/<account_number>'/<key_purpose>'/<key_index>'
//!
//! Where 44' is the standard BIP44 prefix
//!       19788' or 0x4D4C' (1' for the testnets) is Mintlayer's BIP44 registered coin type
//!       `account_number` is the index of an account,
//!       `key_purpose` is if the generated address is for receiving or change purposes and this
//!                     value is 0 or 1 respectively,
//!       `key_index` starts from 0 and it is incremented for each new address

use crate::key_chain::KeyPurpose::{Change, ReceiveFunds};
use common::address::pubkeyhash::{PublicKeyHash, PublicKeyHashError};
use common::address::{Address, AddressError};
use common::chain::config::BIP44_PATH;
use common::chain::ChainConfig;
use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::{Derivable, DerivationError};
use crypto::key::hdkd::derivation_path::DerivationPath;
use crypto::key::PublicKey;
use std::collections::{BTreeMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;
use storage::Backend;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::keys::{KeyPurpose, KeychainUsageState};
use wallet_types::{
    AccountDerivationPathId, AccountId, AccountInfo, AccountKeyPurposeId, DeterministicAccountInfo,
    RootKeyContent, RootKeyId,
};
use zeroize::Zeroize;

/// The number of nodes in a BIP44 path
const BIP44_PATH_LENGTH: usize = 5;
/// The index of key_purpose
const BIP44_KEY_PURPOSE_INDEX: usize = 3;
/// The index of the usable key in the BIP44 hierarchy
const BIP44_KEY_INDEX: usize = 4;
/// Default cryptography type
const DEFAULT_KEY_KIND: ExtendedKeyKind = ExtendedKeyKind::Secp256k1Schnorr;
/// Default size of the number of unused addresses that need to be checked after the
/// last used address.
const LOOKAHEAD_SIZE: u32 = 20;

/// KeyChain errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum KeyChainError {
    #[error("Wallet database error: {0}")]
    DatabaseError(#[from] wallet_storage::Error),
    #[error("Missing database property: {0}")]
    MissingDatabaseProperty(&'static str),
    #[error("Bip39 error: {0}")]
    Bip39(bip39::Error),
    #[error("Key derivation error: {0}")]
    Derivation(#[from] DerivationError),
    #[error("Address error: {0}")]
    Address(#[from] AddressError),
    #[error("Public key hash error: {0}")]
    PubKeyHash(#[from] PublicKeyHashError),
    #[error("Key chain is locked")]
    KeyChainIsLocked,
    #[error("No account found")] // TODO implement display for AccountId
    NoAccountFound(AccountId),
    #[error("Invalid BIP44 derivation path format: {0}")]
    InvalidBip44DerivationPath(DerivationPath),
    #[error("Could not load key chain")]
    CouldNotLoadKeyChain,
    #[error("The provided keys do not belong to the same hierarchy")]
    KeysNotInSameHierarchy,
    #[error("Invalid key purpose index {0}")]
    InvalidKeyPurpose(ChildNumber),
    #[error("Only one root key is supported")]
    OnlyOneRootKeyIsSupported,
    #[error("Cannot issue more keys, lookahead exceeded")]
    LookAheadExceeded,
    #[error("The provided key is not a root in a hierarchy")]
    KeyNotRoot,
}

/// Result type used for the key chain
type KeyChainResult<T> = Result<T, KeyChainError>;

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
        AccountKeyChain::new_from_root_key(
            self.chain_config.clone(),
            db_tx,
            &self.root_key,
            account_index,
            LOOKAHEAD_SIZE,
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
    pub fn get_root_key(&self) -> ExtendedPublicKey {
        self.root_key.to_public_key()
    }
}

/// A child key hierarchy for an AccountKeyChain. This normally implements the receiving and change
/// addresses key chains
#[allow(dead_code)] // TODO remove
pub(crate) struct LeafKeyChain {
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
    public_keys: HashSet<PublicKey>,

    /// All the public key hashes that this key chain holds
    public_key_hashes: HashSet<PublicKeyHash>,

    /// The usage state of this key chain
    usage_state: KeychainUsageState,

    /// A copy of the lookahead size of the account
    lookahead_size: u32,
}

impl LeafKeyChain {
    fn new_empty(
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
            public_keys: HashSet::new(),
            public_key_hashes: HashSet::new(),
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
        let mut public_key_hashes = HashSet::with_capacity(addresses.len());
        for address in addresses.values() {
            let pkh = PublicKeyHash::try_from(address.data(&chain_config)?)?;
            public_key_hashes.insert(pkh);
        }

        let mut public_keys = HashSet::with_capacity(derived_public_keys.len());
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
    pub(crate) fn save_usage_state<B: Backend>(
        &self,
        db_tx: &mut StoreTxRw<B>,
    ) -> KeyChainResult<()> {
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
    pub(crate) fn get_last_derived_index(&self) -> Option<ChildNumber> {
        self.derived_public_keys.last_key_value().map(|(k, _)| *k)
    }

    /// Derive up `lookahead_size` keys starting from the last used index. If the gap from the last
    /// used key to the last derived key is already `lookahead_size`, this method has no effect
    fn top_up<B: Backend>(&mut self, db_tx: &mut StoreTxRw<B>) -> KeyChainResult<()> {
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
    pub(crate) fn set_lookahead_size(&mut self, lookahead_size: u32) {
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

    pub(crate) fn is_public_key_mine(&self, public_key: &PublicKey) -> bool {
        self.public_keys.contains(public_key)
    }

    pub(crate) fn is_public_key_hash_mine(&self, pubkey_hash: &PublicKeyHash) -> bool {
        self.public_key_hashes.contains(pubkey_hash)
    }

    /// Mark a specific key as used in the key pool. This will update the last used key index if
    /// necessary. Returns false if a key was found and set to used.
    pub(crate) fn mark_key_pool_pubkey_as_used<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        public_key: &ExtendedPublicKey,
    ) -> KeyChainResult<bool> {
        // Check if public key is in the key pool
        if self.is_pubkey_mine_in_key_pool(public_key) {
            // Get the key index of the public key, this should always be Some
            let key_index = public_key.get_derivation_path().as_vec().last().expect("The provided public key belongs to this key chain, hence it should always have a key index");
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
    pub(crate) fn get_last_used(&self) -> Option<ChildNumber> {
        self.usage_state.get_last_used()
    }

    /// Get the index of the last issued key or None if no key is issued
    #[allow(dead_code)] // TODO remove
    pub(crate) fn get_last_issued(&self) -> Option<ChildNumber> {
        self.usage_state.get_last_issued()
    }
}

#[allow(dead_code)] // TODO remove
/// This key chain contains a pool of pre-generated keys and addresses for the usage in a wallet
pub struct AccountKeyChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The account key from which all the addresses are derived
    account_pubkey: ExtendedPublicKey,

    /// The master/root key that this account key was derived from
    root_hierarchy_key: Option<ExtendedPublicKey>,

    /// Key chain for receiving funds
    receiving_key_chain: LeafKeyChain,

    /// Key chain for change addresses
    change_key_chain: LeafKeyChain,

    /// The number of unused addresses that need to be checked after the last used address
    lookahead_size: u32,
}

impl AccountKeyChain {
    fn new_from_root_key<B: Backend>(
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
            ReceiveFunds,
            account_pubkey.clone().derive_child(ReceiveFunds.get_deterministic_index())?,
            lookahead_size,
        );
        receiving_key_chain.save_usage_state(db_tx)?;

        let change_key_chain = LeafKeyChain::new_empty(
            chain_config.clone(),
            account_id,
            Change,
            account_pubkey.clone().derive_child(Change.get_deterministic_index())?,
            lookahead_size,
        );
        change_key_chain.save_usage_state(db_tx)?;

        let mut new_account = AccountKeyChain {
            chain_config,
            account_pubkey,
            root_hierarchy_key: Some(root_key.to_public_key()),
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
            Self::load_leaf_keys(chain_config.clone(), &account_info, db_tx, id)?;

        Ok(AccountKeyChain {
            chain_config,
            account_pubkey,
            root_hierarchy_key: account_info.get_root_hierarchy_key().clone(),
            receiving_key_chain,
            change_key_chain,
            lookahead_size: account_info.get_lookahead_size(),
        })
    }

    fn load_leaf_keys<B: Backend>(
        chain_config: Arc<ChainConfig>,
        account_info: &DeterministicAccountInfo,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> KeyChainResult<(LeafKeyChain, LeafKeyChain)> {
        let mut receiving_addresses = BTreeMap::new();
        let mut change_addresses = BTreeMap::new();

        for (address_id, address) in db_tx.get_addresses(id)? {
            let (purpose, key_index) = Self::get_purpose_and_index(&address_id.into_item_id())?;
            let old_value = match purpose {
                ReceiveFunds => receiving_addresses.insert(key_index, address),
                Change => change_addresses.insert(key_index, address),
            };
            if old_value.is_some() {
                return Err(KeyChainError::CouldNotLoadKeyChain);
            }
        }

        let mut receiving_public_keys = BTreeMap::new();
        let mut change_public_keys = BTreeMap::new();
        for (pubkey_id, xpub) in db_tx.get_public_keys(id)? {
            let (purpose, key_index) = Self::get_purpose_and_index(&pubkey_id.into_item_id())?;
            let old_value = match purpose {
                ReceiveFunds => receiving_public_keys.insert(key_index, xpub),
                Change => change_public_keys.insert(key_index, xpub),
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
                ReceiveFunds,
                account_pubkey.clone().derive_child(ReceiveFunds.get_deterministic_index())?,
                receiving_addresses,
                receiving_public_keys,
                usage_states.remove(&ReceiveFunds).ok_or(
                    KeyChainError::MissingDatabaseProperty("ReceiveFunds usage state"),
                )?,
                account_info.get_lookahead_size(),
            )?,
            LeafKeyChain::new_from_parts(
                chain_config,
                id.clone(),
                Change,
                account_pubkey.clone().derive_child(Change.get_deterministic_index())?,
                change_addresses,
                change_public_keys,
                usage_states
                    .remove(&Change)
                    .ok_or(KeyChainError::MissingDatabaseProperty("Change usage state"))?,
                account_info.get_lookahead_size(),
            )?,
        ))
    }

    pub fn get_account_id(&self) -> AccountId {
        AccountId::new_from_xpub(&self.account_pubkey)
    }

    pub fn get_account_key(&self) -> ExtendedPublicKey {
        self.account_pubkey.clone()
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
    pub(crate) fn get_private_key(
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
    pub(crate) fn get_leaf_key_chain(&self, purpose: KeyPurpose) -> &LeafKeyChain {
        match purpose {
            ReceiveFunds => &self.receiving_key_chain,
            Change => &self.change_key_chain,
        }
    }

    /// Get the mutable leaf key chain for a particular key purpose. This is used internally with
    /// database persistence done externally.
    fn get_leaf_key_chain_mut(&mut self, purpose: KeyPurpose) -> &mut LeafKeyChain {
        match purpose {
            ReceiveFunds => &mut self.receiving_key_chain,
            Change => &mut self.change_key_chain,
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
    fn top_up_all<B: Backend>(&mut self, db_tx: &mut StoreTxRw<B>) -> KeyChainResult<()> {
        for purpose in KeyPurpose::ALL {
            self.get_leaf_key_chain_mut(purpose).top_up(db_tx)?;
        }
        Ok(())
    }

    pub(crate) fn get_account_info(&self) -> AccountInfo {
        AccountInfo::Deterministic(DeterministicAccountInfo::new(
            self.root_hierarchy_key.clone(),
            self.account_pubkey.clone(),
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
    pub fn mark_as_used<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        public_key: &ExtendedPublicKey,
    ) -> KeyChainResult<bool> {
        for purpose in KeyPurpose::ALL {
            let leaf_keys = self.get_leaf_key_chain_mut(purpose);
            if leaf_keys.mark_key_pool_pubkey_as_used(db_tx, public_key)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn get_purpose_and_index(
        derivation_path: &DerivationPath,
    ) -> KeyChainResult<(KeyPurpose, ChildNumber)> {
        // Check that derivation path has the expected number of nodes
        if derivation_path.len() != BIP44_PATH_LENGTH {
            return Err(KeyChainError::InvalidBip44DerivationPath(
                derivation_path.clone(),
            ));
        }
        let path = derivation_path.as_vec();
        // Calculate the key purpose and index
        let purpose = KeyPurpose::try_from(path[BIP44_KEY_PURPOSE_INDEX])
            .map_err(KeyChainError::InvalidKeyPurpose)?;
        let key_index = path[BIP44_KEY_INDEX];
        Ok((purpose, key_index))
    }
}

/// Create a deterministic path for an account identified by the `account_index`
fn make_account_path(chain_config: &ChainConfig, account_index: ChildNumber) -> DerivationPath {
    // The path is m/44'/<coin_type>'/<account_index>'
    let path = vec![BIP44_PATH, chain_config.bip44_coin_type(), account_index];
    path.try_into().expect("Path creation should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::config::create_unit_test_config;
    use crypto::key::hdkd::u31::U31;
    use crypto::key::secp256k1::Secp256k1PublicKey;
    use crypto::key::PublicKey;
    use rstest::rstest;
    use std::str::FromStr;
    use test_utils::assert_encoded_eq;
    use wallet_storage::{DefaultBackend, Store, TransactionRw, Transactional};

    const ZERO_H: ChildNumber = ChildNumber::from_hardened(U31::from_u32_with_msb(0).0);
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[rstest]
    #[case(
        KeyPurpose::ReceiveFunds,
        "m/44'/19788'/0'/0/0",
        "8000002c80004d4c800000000000000000000000",
        "b870ce52f8ccb3204e7fcdbb84f122fee29ce3c462750c54d411201baa4cf23c",
        "03bf6f8d52dade77f95e9c6c9488fd8492a99c09ff23095caffb2e6409d1746ade",
        "0ae454a1024d0ddb9e10d23479cf8ef39fb400727fabd17844bd8362b1c70d7d"
    )]
    #[case(
        KeyPurpose::Change,
        "m/44'/19788'/0'/1/0",
        "8000002c80004d4c800000000000000100000000",
        "f2b1cb7118920fe9b3a0470bd67588fb4bdd4af1355ff39171ed41e968a8621b",
        "035df5d551bac1d61a5473615a70eb17b2f4ccbf7e354166639428941e4dbbcd81",
        "8d62d08e7a23e4b510b970ffa84b4a5ed22e6c03faecf32c5dafaf092938516d"
    )]
    #[case(
        KeyPurpose::ReceiveFunds,
        "m/44'/19788'/0'/0/1",
        "8000002c80004d4c800000000000000000000001",
        "f73943cf443cd5cdd6c35e3fc1c8f039dd92c29a3d9fc1f56c5145ad67535fba",
        "030d1d07a8e45110d14f4e2c8623e8db556c11a90c0aac6be9a88f2464e446ee95",
        "7ed12073a4cc61d8a79f3dc0dfc5ca1a23d9ce1fe3c1e92d3b6939cd5848a390"
    )]
    fn key_chain_creation(
        #[case] purpose: KeyPurpose,
        #[case] path_str: &str,
        #[case] path_encoded_str: &str,
        #[case] secret: &str,
        #[case] public: &str,
        #[case] chaincode: &str,
    ) {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();
        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(chain_config, &mut db_tx, MNEMONIC, None).unwrap();

        let mut key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();
        key_chain.top_up_all(&mut db_tx).unwrap();
        db_tx.commit().unwrap();

        // This public key should belong to the key chain
        let pk: PublicKey =
            Secp256k1PublicKey::from_bytes(&hex::decode(public).unwrap()).unwrap().into();
        let pkh = PublicKeyHash::from(&pk);
        assert!(key_chain.is_public_key_hash_mine(&pkh));

        // This zeroed pub key hash should not belong to the key chain
        let pkh = PublicKeyHash::zero();
        assert!(!key_chain.is_public_key_hash_mine(&pkh));

        let mut db_tx = db.transaction_rw(None).unwrap();
        let path = DerivationPath::from_str(path_str).unwrap();
        // Derive expected key
        let pk = {
            let key_index = path.as_vec().last().unwrap().get_index();
            // Derive previous key if necessary
            if key_index > 0 {
                for _ in 0..key_index {
                    let _ = key_chain.issue_key(&mut db_tx, purpose).unwrap();
                }
            }
            key_chain.issue_key(&mut db_tx, purpose).unwrap()
        };
        assert_eq!(pk.get_derivation_path().to_string(), path_str.to_string());
        let sk = key_chain.get_private_key(&master_key_chain.root_key, &pk).unwrap();
        let pk2 = ExtendedPublicKey::from_private_key(&sk);
        assert_eq!(pk2.get_derivation_path().to_string(), path_str.to_string());
        assert_eq!(pk, pk2);
        assert_eq!(sk.get_derivation_path(), &path);
        assert_eq!(pk.get_derivation_path(), &path);
        let path_len = path.len();
        assert_encoded_eq(
            &sk,
            format!("00{path_len:02x}{path_encoded_str}{chaincode}{secret}").as_str(),
        );
        assert_encoded_eq(
            &pk,
            format!("00{path_len:02x}{path_encoded_str}{chaincode}{public}").as_str(),
        );
    }

    #[rstest]
    #[case(KeyPurpose::ReceiveFunds)]
    #[case(KeyPurpose::Change)]
    fn key_lookahead(#[case] purpose: KeyPurpose) {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();
        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(chain_config, &mut db_tx, MNEMONIC, None).unwrap();
        let mut key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();
        db_tx.commit().unwrap();

        let id = key_chain.get_account_id();

        let mut db_tx = db.transaction_rw(None).unwrap();
        key_chain.set_lookahead_size(&mut db_tx, 5).unwrap();
        assert_eq!(key_chain.get_lookahead_size(), 5);

        // Issue new addresses until the lookahead size is reached
        for _ in 0..5 {
            key_chain.issue_address(&mut db_tx, purpose).unwrap();
        }
        assert_eq!(
            key_chain.issue_address(&mut db_tx, purpose),
            Err(KeyChainError::LookAheadExceeded)
        );
        db_tx.commit().unwrap();
        drop(key_chain);

        let mut key_chain = master_key_chain
            .load_keychain_from_database(&db.transaction_ro().unwrap(), &id)
            .unwrap();
        assert_eq!(key_chain.get_lookahead_size(), 5);
        assert_eq!(key_chain.get_leaf_key_chain(purpose).get_last_used(), None);
        assert_eq!(
            key_chain.get_leaf_key_chain(purpose).get_last_issued(),
            Some(ChildNumber::from_normal(U31::from_u32_with_msb(4).0))
        );

        let mut db_tx = db.transaction_rw(None).unwrap();

        // Increase the lookahead size
        key_chain.set_lookahead_size(&mut db_tx, 10).unwrap();

        // Should be able to issue more addresses
        for _ in 0..5 {
            key_chain.issue_address(&mut db_tx, purpose).unwrap();
        }
        assert_eq!(
            key_chain.issue_address(&mut db_tx, purpose),
            Err(KeyChainError::LookAheadExceeded)
        );
    }

    #[rstest]
    #[case(KeyPurpose::ReceiveFunds)]
    #[case(KeyPurpose::Change)]
    fn top_up_and_lookahead(#[case] purpose: KeyPurpose) {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();
        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(chain_config, &mut db_tx, MNEMONIC, None).unwrap();
        let key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();
        let id = key_chain.get_account_id();
        db_tx.commit().unwrap();
        drop(key_chain);

        let mut key_chain = master_key_chain
            .load_keychain_from_database(&db.transaction_ro().unwrap(), &id)
            .unwrap();

        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(19);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(leaf_keys.usage_state.get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state.get_last_used(), None);
        }

        let mut db_tx = db.transaction_rw(None).unwrap();

        key_chain.set_lookahead_size(&mut db_tx, 5).unwrap();
        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(19);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(leaf_keys.usage_state.get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state.get_last_used(), None);
        }

        key_chain.set_lookahead_size(&mut db_tx, 30).unwrap();
        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(29);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(leaf_keys.usage_state.get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state.get_last_used(), None);
        }

        key_chain.set_lookahead_size(&mut db_tx, 10).unwrap();
        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(29);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(leaf_keys.usage_state.get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state.get_last_used(), None);
        }

        let mut issued_key = key_chain.issue_key(&mut db_tx, purpose).unwrap();

        // Mark the last key as used
        assert!(key_chain.mark_as_used(&mut db_tx, &issued_key).unwrap());

        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(29);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(
                leaf_keys.usage_state.get_last_issued(),
                Some(ChildNumber::from_index_with_hardened_bit(0))
            );
            assert_eq!(
                leaf_keys.usage_state.get_last_used(),
                Some(ChildNumber::from_index_with_hardened_bit(0))
            );
        }

        // Derive keys until lookahead
        while let Ok(k) = key_chain.issue_key(&mut db_tx, purpose) {
            issued_key = k;
        }

        // Mark the last key as used
        assert!(key_chain.mark_as_used(&mut db_tx, &issued_key).unwrap());

        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(29);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(
                leaf_keys.usage_state.get_last_issued(),
                Some(ChildNumber::from_index_with_hardened_bit(10))
            );
            assert_eq!(
                leaf_keys.usage_state.get_last_used(),
                Some(ChildNumber::from_index_with_hardened_bit(10))
            );
        }
    }
}

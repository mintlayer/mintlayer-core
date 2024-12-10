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

use crate::key_chain::{KeyChainError, KeyChainResult};
use common::address::Address;
use common::chain::ChainConfig;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::{Derivable, DerivationError};
use crypto::key::hdkd::u31::U31;
use crypto::vrf::{ExtendedVRFPublicKey, VRFPublicKey};
use std::collections::BTreeMap;
use std::sync::Arc;
use utils::const_value::ConstValue;
use utils::ensure;
use wallet_storage::{WalletStorageReadLocked, WalletStorageWriteLocked};
use wallet_types::account_info::AccountVrfKeys;
use wallet_types::keys::KeychainUsageState;
use wallet_types::AccountId;

/// A child key hierarchy for an AccountKeyChain. This normally implements the receiving and change
/// addresses key chains. It uses soft derivation to generate addresses (xpub).
pub struct VrfKeySoftChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The account id this leaf key chain belongs to
    account_id: AccountId,

    /// The parent key of this key chain
    parent_pubkey: ConstValue<ExtendedVRFPublicKey>,

    /// The parent key of this key chain
    legacy_pubkey: ConstValue<ExtendedVRFPublicKey>,

    /// The derived keys for the receiving funds or change. Those are derived as needed.
    derived_public_keys: BTreeMap<ChildNumber, ExtendedVRFPublicKey>,

    /// All the public key that this key chain holds
    public_key_to_index: BTreeMap<VRFPublicKey, ChildNumber>,

    /// The usage state of this key chain
    usage_state: KeychainUsageState,
}

impl VrfKeySoftChain {
    pub fn new_empty(
        chain_config: Arc<ChainConfig>,
        account_id: AccountId,
        parent_pubkey: ExtendedVRFPublicKey,
        legacy_pubkey: ExtendedVRFPublicKey,
    ) -> Self {
        Self {
            chain_config,
            account_id,
            parent_pubkey: parent_pubkey.into(),
            derived_public_keys: BTreeMap::new(),
            public_key_to_index: BTreeMap::new(),
            legacy_pubkey: legacy_pubkey.into(),
            usage_state: KeychainUsageState::default(),
        }
    }

    fn new_from_parts(
        chain_config: Arc<ChainConfig>,
        account_id: AccountId,
        parent_pubkey: ExtendedVRFPublicKey,
        derived_public_keys: BTreeMap<ChildNumber, ExtendedVRFPublicKey>,
        usage_state: KeychainUsageState,
        legacy_pubkey: ExtendedVRFPublicKey,
        lookahead_size: u32,
    ) -> KeyChainResult<Self> {
        let public_key_to_index: BTreeMap<VRFPublicKey, ChildNumber> = derived_public_keys
            .iter()
            .map(|(idx, xpub)| (xpub.clone().into_public_key(), *idx))
            .collect();

        let mut vrf_chain = Self {
            chain_config,
            account_id,
            parent_pubkey: parent_pubkey.into(),
            derived_public_keys,
            public_key_to_index,
            legacy_pubkey: legacy_pubkey.into(),
            usage_state,
        };
        vrf_chain.top_up(lookahead_size)?;
        Ok(vrf_chain)
    }

    /// Persist the usage state to the database
    pub fn save_usage_state(
        &self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> KeyChainResult<()> {
        db_tx
            .set_vrf_keychain_usage_state(&self.account_id, &self.usage_state)
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
    fn derive_key(&self, key_index: U31) -> KeyChainResult<ExtendedVRFPublicKey> {
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

    /// Derives and adds a key to his key chain. This does not affect the last used and issued state
    fn derive_and_add_key(&mut self, key_index: U31) -> KeyChainResult<ExtendedVRFPublicKey> {
        // Get the public key from the key pool if available
        if let Some(pub_key) = self.derived_public_keys.get(&ChildNumber::from_normal(key_index)) {
            return Ok(pub_key.clone());
        }

        // Derive the new extended public key
        let derived_key = self.derive_key(key_index)?;
        // Just the public key
        let public_key = derived_key.clone().into_public_key();

        // Add key and address the maps
        self.derived_public_keys
            .insert(ChildNumber::from_normal(key_index), derived_key.clone());
        self.public_key_to_index.insert(public_key, ChildNumber::from_normal(key_index));

        Ok(derived_key)
    }

    /// Get the last derived key index
    pub fn get_last_derived_index(&self) -> Option<ChildNumber> {
        self.derived_public_keys.keys().last().copied()
    }

    pub fn get_derived_xpub_from_public_key(
        &self,
        pub_key: &VRFPublicKey,
    ) -> Option<&ExtendedVRFPublicKey> {
        if self.legacy_pubkey.public_key() == pub_key {
            return Some(&self.legacy_pubkey);
        }

        self.public_key_to_index
            .get(pub_key)
            .and_then(|child_number| self.derived_public_keys.get(child_number))
    }

    /// Get the extended public key provided a public key or None if no key found
    pub fn get_child_num_from_public_key(&self, pub_key: &VRFPublicKey) -> Option<ChildNumber> {
        self.public_key_to_index.get(pub_key).copied()
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
        self.top_up(lookahead_size)
    }

    /// Get the index of the last used key or None if no key is used
    pub fn last_used(&self) -> Option<U31> {
        self.usage_state.last_used()
    }

    /// Get the index of the last issued key or None if no key is issued
    pub fn last_issued(&self) -> Option<U31> {
        self.usage_state.last_issued()
    }

    pub fn get_legacy_vrf_public_key(&self) -> Address<VRFPublicKey> {
        Address::new(&self.chain_config, self.legacy_pubkey.public_key().clone())
            .expect("addressable")
    }

    /// Issue a new key
    pub fn issue_new(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        lookahead_size: u32,
    ) -> KeyChainResult<(ChildNumber, ExtendedVRFPublicKey)> {
        let new_issued_index = self.get_new_issued_index(lookahead_size)?;

        let key = self.derive_and_add_key(new_issued_index)?;

        let index = ChildNumber::from_normal(new_issued_index);

        logging::log::debug!(
            "new vrf address: {}, index: {}",
            Address::new(&self.chain_config, key.clone().into_public_key()).expect("addressable"),
            new_issued_index,
        );

        self.usage_state.increment_up_to_last_issued(new_issued_index);
        self.save_usage_state(db_tx)?;

        Ok((index, key))
    }

    pub fn get_all_issued_keys(&self) -> BTreeMap<ChildNumber, (Address<VRFPublicKey>, bool)> {
        let last_issued = match self.usage_state.last_issued() {
            Some(index) => index,
            None => return BTreeMap::new(),
        };

        let last_issued = ChildNumber::from_normal(last_issued);

        self.derived_public_keys
            .clone()
            .into_iter()
            .filter(|(index, _key)| *index <= last_issued)
            .map(|(index, key)| {
                (
                    index,
                    (
                        Address::new(&self.chain_config, key.public_key().clone())
                            .expect("addressable"),
                        self.usage_state.last_used().is_some_and(|used| used >= index.get_index()),
                    ),
                )
            })
            .collect()
    }
}

pub trait VrfKeyChain
where
    Self: Sized,
{
    fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
        lookahead_size: u32,
    ) -> KeyChainResult<Self>;

    /// Derive up `lookahead_size` keys starting from the last used index. If the gap from the last
    /// used key to the last derived key is already `lookahead_size`, this method has no effect
    fn top_up(&mut self, lookahead_size: u32) -> KeyChainResult<()>;

    fn mark_pubkey_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key: &VRFPublicKey,
        lookahead_size: u32,
    ) -> KeyChainResult<bool>;
}

impl VrfKeyChain for VrfKeySoftChain {
    fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
        lookahead_size: u32,
    ) -> KeyChainResult<VrfKeySoftChain> {
        let AccountVrfKeys {
            account_vrf_key,
            legacy_vrf_key,
        } = db_tx
            .get_account_vrf_public_keys(id)?
            .ok_or(KeyChainError::CouldNotLoadKeyChain)?;

        let usage = db_tx
            .get_vrf_keychain_usage_state(id)?
            .ok_or(KeyChainError::CouldNotLoadKeyChain)?;

        let public_keys = (0..=usage.last_issued().map_or(0, |issued| issued.into_u32()))
            .map(|index| {
                let child_number = ChildNumber::from_index_with_hardened_bit(index);
                Ok((
                    child_number,
                    account_vrf_key.clone().derive_child(child_number)?,
                ))
            })
            .collect::<Result<_, DerivationError>>()?;

        VrfKeySoftChain::new_from_parts(
            chain_config.clone(),
            id.clone(),
            account_vrf_key,
            public_keys,
            usage,
            legacy_vrf_key,
            lookahead_size,
        )
    }

    /// Derive up `lookahead_size` keys starting from the last used index. If the gap from the last
    /// used key to the last derived key is already `lookahead_size`, this method has no effect
    fn top_up(&mut self, lookahead_size: u32) -> KeyChainResult<()> {
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
                self.derive_and_add_key(index)?;
            }
        }

        Ok(())
    }

    fn mark_pubkey_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key: &VRFPublicKey,
        lookahead_size: u32,
    ) -> KeyChainResult<bool> {
        if let Some(child_num) = self.get_child_num_from_public_key(public_key) {
            self.mark_child_key_as_used(db_tx, child_num, lookahead_size)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct EmptyVrfKeyChain;

impl VrfKeyChain for EmptyVrfKeyChain {
    fn load_from_database(
        _chain_config: Arc<ChainConfig>,
        _db_tx: &impl WalletStorageReadLocked,
        _id: &AccountId,
        _lookahead_size: u32,
    ) -> KeyChainResult<Self> {
        Ok(Self {})
    }

    fn top_up(&mut self, _lookahead_size: u32) -> KeyChainResult<()> {
        Ok(())
    }

    fn mark_pubkey_as_used(
        &mut self,
        _db_tx: &mut impl WalletStorageWriteLocked,
        _public_key: &VRFPublicKey,
        _lookahead_size: u32,
    ) -> KeyChainResult<bool> {
        Ok(false)
    }
}

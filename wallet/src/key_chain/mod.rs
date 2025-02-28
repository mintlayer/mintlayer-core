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
//! m/44'/19788'/<account_number>'/<key_purpose>/<key_index>
//!
//! Where 44' is the standard BIP44 prefix
//!       19788' or 0x4D4C' (1' for the testnets) is Mintlayer's BIP44 registered coin type
//!       `account_number` is the index of an account,
//!       `key_purpose` is if the generated address is for receiving or change purposes and this
//!                     value is 0 or 1 respectively,
//!       `key_index` starts from 0 and it is incremented for each new address

mod account_key_chain;
mod leaf_key_chain;
mod master_key_chain;
mod vrf_key_chain;
mod with_purpose;

use std::collections::BTreeMap;
use std::sync::Arc;

pub use account_key_chain::AccountKeyChainImpl;
use common::chain::classic_multisig::ClassicMultisigChallenge;
use crypto::key::hdkd::u31::U31;
use crypto::key::{PrivateKey, PublicKey};
use crypto::vrf::{ExtendedVRFPrivateKey, ExtendedVRFPublicKey, VRFKeyKind, VRFPublicKey};
pub use master_key_chain::MasterKeyChain;

use common::address::pubkeyhash::{PublicKeyHash, PublicKeyHashError};
use common::address::{Address, AddressError, RpcAddress};
use common::chain::config::BIP44_PATH;
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::{ExtendedKeyKind, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::DerivationError;
use crypto::key::hdkd::derivation_path::DerivationPath;
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteLocked,
    WalletStorageWriteUnlocked,
};
use wallet_types::account_id::AccountPublicKey;
use wallet_types::account_info::{StandaloneAddressDetails, StandaloneAddresses};
use wallet_types::keys::{KeyPurpose, KeyPurposeError};
use wallet_types::{AccountId, AccountInfo, KeychainUsageState};

use self::vrf_key_chain::{EmptyVrfKeyChain, VrfKeySoftChain};

/// The number of nodes in a BIP44 path
pub const BIP44_PATH_LENGTH: usize = 5;
/// The index of key_purpose
pub const BIP44_KEY_PURPOSE_INDEX: usize = 3;
/// The index of the usable key in the BIP44 hierarchy
pub const BIP44_KEY_INDEX: usize = 4;

/// Default cryptography type
const DEFAULT_KEY_KIND: ExtendedKeyKind = ExtendedKeyKind::Secp256k1Schnorr;
const DEFAULT_VRF_KEY_KIND: VRFKeyKind = VRFKeyKind::Schnorrkel;
/// Default size of the number of unused addresses that need to be checked after the
/// last used address.
pub const LOOKAHEAD_SIZE: u32 = 20;

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
    #[error("KeyChain not initialized missing root keys")]
    KeyChainNotInitialized,
    #[error("Cannot issue more keys, lookahead exceeded")]
    LookAheadExceeded,
    #[error("The provided key is not a root in a hierarchy")]
    KeyNotRoot,
    #[error("No private key found")]
    NoPrivateKeyFound,
    #[error("No VRF private key found")]
    NoVRFPrivateKeyFound,
    #[error("No standalone address found for: {0}")]
    NoStandaloneAddressFound(RpcAddress<Destination>),
    #[error("Standalone address already exists: {0}")]
    StandaloneAddressAlreadyExists(RpcAddress<Destination>),
}

pub enum FoundPubKey {
    Hierarchy(ExtendedPublicKey),
    Standalone(AccountPublicKey),
}

impl FoundPubKey {
    pub fn into_public_key(self) -> PublicKey {
        match self {
            Self::Hierarchy(xpub) => xpub.into_public_key(),
            Self::Standalone(acc_pk) => acc_pk.into_item_id(),
        }
    }
}

pub type AccountKeyChainImplSoftware = AccountKeyChainImpl<VrfKeySoftChain>;
pub type AccountKeyChainImplHardware = AccountKeyChainImpl<EmptyVrfKeyChain>;

pub trait AccountKeyChains
where
    Self: Sized,
{
    fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
        account_info: &AccountInfo,
    ) -> KeyChainResult<Self>;

    fn find_public_key(&self, destination: &Destination) -> Option<FoundPubKey>;

    fn find_multisig_challenge(
        &self,
        destination: &Destination,
    ) -> Option<&ClassicMultisigChallenge>;

    fn account_index(&self) -> U31;

    fn get_account_id(&self) -> AccountId;

    fn account_public_key(&self) -> &ExtendedPublicKey;

    /// Return the next unused address and don't mark it as issued
    fn next_unused_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> KeyChainResult<(ChildNumber, Address<Destination>)>;

    /// Issue a new address that hasn't been used before
    fn issue_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> KeyChainResult<(ChildNumber, Address<Destination>)>;

    /// Issue a new derived key that hasn't been used before
    fn issue_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> KeyChainResult<ExtendedPublicKey>;

    /// Reload the sub chain keys from DB to restore the cache
    /// Should be called after issuing a new key but not using committing it to the DB
    fn reload_keys(&mut self, db_tx: &impl WalletStorageReadLocked) -> KeyChainResult<()>;

    // Return true if the provided destination belongs to this key chain
    fn is_destination_mine(&self, destination: &Destination) -> bool;

    // Return true if we have the private key for the provided destination
    fn has_private_key_for_destination(&self, destination: &Destination) -> bool;

    // Return true if the provided public key belongs to this key chain
    fn is_public_key_mine(&self, public_key: &PublicKey) -> bool;

    // Return true if the provided public key hash belongs to this key chain
    fn is_public_key_hash_mine(&self, pubkey_hash: &PublicKeyHash) -> bool;

    // Return true if the provided public key hash is one the standalone added keys
    fn is_public_key_hash_watched(&self, pubkey_hash: PublicKeyHash) -> bool;

    // Return true if the provided public key hash belongs to this key chain
    // or is one the standalone added keys
    fn is_public_key_hash_mine_or_watched(&self, pubkey_hash: PublicKeyHash) -> bool;

    /// Find the corresponding public key for a given public key hash
    fn get_public_key_from_public_key_hash(&self, pubkey_hash: &PublicKeyHash)
        -> Option<PublicKey>;

    /// Derive addresses until there are lookahead unused ones
    fn top_up_all(&mut self, db_tx: &mut impl WalletStorageWriteLocked) -> KeyChainResult<()>;

    fn lookahead_size(&self) -> u32;

    /// Marks a public key as being used. Returns true if a key was found and set to used.
    fn mark_public_key_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key: &PublicKey,
    ) -> KeyChainResult<bool>;

    fn mark_public_key_hash_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        pub_key_hash: &PublicKeyHash,
    ) -> KeyChainResult<bool>;

    /// Marks a vrf public key as being used. Returns true if a key was found and set to used.
    fn mark_vrf_public_key_as_used(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        public_key: &VRFPublicKey,
    ) -> KeyChainResult<bool>;

    fn get_multisig_challenge(
        &self,
        destination: &Destination,
    ) -> Option<&ClassicMultisigChallenge>;

    /// Add, rename or delete a label for a standalone address not from the keys derived from this account
    fn standalone_address_label_rename(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        new_address: Destination,
        new_label: Option<String>,
    ) -> KeyChainResult<()>;

    /// Adds a new public key hash to be watched, standalone from the keys derived from this account
    fn add_standalone_watch_only_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        new_address: PublicKeyHash,
        label: Option<String>,
    ) -> KeyChainResult<()>;

    ///  Adds a new private key to be watched, standalone from the keys derived from this account
    fn add_standalone_private_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        new_private_key: PrivateKey,
        label: Option<String>,
    ) -> KeyChainResult<()>;

    /// Adds a multisig to be watched
    fn add_standalone_multisig(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        challenge: ClassicMultisigChallenge,
        label: Option<String>,
    ) -> KeyChainResult<PublicKeyHash>;

    fn get_all_issued_addresses(&self) -> BTreeMap<ChildNumber, Address<Destination>>;

    fn get_all_standalone_addresses(&self) -> StandaloneAddresses;

    fn get_all_standalone_address_details(
        &self,
        address: Destination,
    ) -> Option<(Destination, StandaloneAddressDetails)>;

    fn get_addresses_usage_state(&self) -> &KeychainUsageState;
}

pub trait VRFAccountKeyChains {
    fn issue_vrf_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> KeyChainResult<(ChildNumber, ExtendedVRFPublicKey)>;

    fn get_vrf_private_key_for_public_key(
        &self,
        public_key: &VRFPublicKey,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<Option<ExtendedVRFPrivateKey>>;

    fn get_all_issued_vrf_public_keys(
        &self,
    ) -> BTreeMap<ChildNumber, (Address<VRFPublicKey>, bool)>;

    fn get_legacy_vrf_public_key(&self) -> Address<VRFPublicKey>;

    fn get_private_key_for_destination(
        &self,
        destination: &Destination,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> KeyChainResult<Option<PrivateKey>>;
}

/// Result type used for the key chain
type KeyChainResult<T> = Result<T, KeyChainError>;

/// Create a deterministic path for an account identified by the `account_index`
pub fn make_account_path(chain_config: &ChainConfig, account_index: U31) -> DerivationPath {
    // The path is m/44'/<coin_type>'/<account_index>'
    let path = vec![
        BIP44_PATH,
        chain_config.bip44_coin_type(),
        ChildNumber::from_hardened(account_index),
    ];
    debug_assert!(path.iter().all(ChildNumber::is_hardened));
    path.try_into().expect("Path creation should not fail")
}

pub const VRF_INDEX: ChildNumber = ChildNumber::from_hardened(U31::TWO);

/// Create a deterministic path for the default VRF key for the account
pub fn make_path_to_vrf_key(chain_config: &ChainConfig, account_index: U31) -> DerivationPath {
    // The path is m/44'/<coin_type>'/<account_index>'/2'/0'.
    // Index 2' is used to ensure that the key is different from potential receive/change keys.
    // The VRF key is only needed to create pool transactions and to generate PoS blocks,
    // and in both cases the private key should be unlocked (so using the hard derivation is not a problem).
    let path = vec![
        BIP44_PATH,
        chain_config.bip44_coin_type(),
        ChildNumber::from_hardened(account_index),
        VRF_INDEX,
        ChildNumber::from_hardened(U31::ZERO),
    ];
    debug_assert!(path.iter().all(ChildNumber::is_hardened));
    path.try_into().expect("Path creation should not fail")
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
    let path = derivation_path.as_slice();
    // Calculate the key purpose and index
    let purpose = KeyPurpose::try_from(path[BIP44_KEY_PURPOSE_INDEX]).map_err(|err| {
        let KeyPurposeError::KeyPurposeConversion(num) = err;
        KeyChainError::InvalidKeyPurpose(num)
    })?;
    let key_index = path[BIP44_KEY_INDEX];
    Ok((purpose, key_index))
}

#[cfg(test)]
mod tests;

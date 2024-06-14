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

pub use account_key_chain::AccountKeyChainImpl;
use common::chain::classic_multisig::ClassicMultisigChallenge;
use crypto::key::hdkd::u31::U31;
use crypto::vrf::VRFKeyKind;
pub use master_key_chain::MasterKeyChain;

use common::address::pubkeyhash::PublicKeyHashError;
use common::address::{AddressError, RpcAddress};
use common::chain::config::BIP44_PATH;
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::{ExtendedKeyKind, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::DerivationError;
use crypto::key::hdkd::derivation_path::DerivationPath;
use wallet_types::account_id::AccountPublicKey;
use wallet_types::keys::{KeyPurpose, KeyPurposeError};
use wallet_types::AccountId;

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

pub trait AccountKeyChains {
    fn find_public_key(&self, destination: &Destination) -> Option<FoundPubKey>;

    fn find_multisig_challenge(
        &self,
        destination: &Destination,
    ) -> Option<&ClassicMultisigChallenge>;
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

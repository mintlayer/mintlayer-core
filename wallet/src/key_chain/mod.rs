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

mod account_key_chain;
mod leaf_key_chain;
mod master_key_chain;

pub use account_key_chain::AccountKeyChain;
pub use master_key_chain::MasterKeyChain;

use common::address::pubkeyhash::PublicKeyHashError;
use common::address::AddressError;
use common::chain::config::BIP44_PATH;
use common::chain::ChainConfig;
use crypto::key::extended::ExtendedKeyKind;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::DerivationError;
use crypto::key::hdkd::derivation_path::DerivationPath;
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
    #[error("Only one root key is supported")]
    OnlyOneRootKeyIsSupported,
    #[error("Cannot issue more keys, lookahead exceeded")]
    LookAheadExceeded,
    #[error("The provided key is not a root in a hierarchy")]
    KeyNotRoot,
}

/// Result type used for the key chain
type KeyChainResult<T> = Result<T, KeyChainError>;

/// Create a deterministic path for an account identified by the `account_index`
fn make_account_path(chain_config: &ChainConfig, account_index: ChildNumber) -> DerivationPath {
    // The path is m/44'/<coin_type>'/<account_index>'
    let path = vec![BIP44_PATH, chain_config.bip44_coin_type(), account_index];
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
mod tests {
    use super::*;
    use common::address::pubkeyhash::PublicKeyHash;
    use common::chain::config::create_unit_test_config;
    use crypto::key::extended::ExtendedPublicKey;
    use crypto::key::hdkd::derivable::Derivable;
    use crypto::key::hdkd::u31::U31;
    use crypto::key::secp256k1::Secp256k1PublicKey;
    use crypto::key::PublicKey;
    use rstest::rstest;
    use std::str::FromStr;
    use std::sync::Arc;
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
            let key_index = path.as_slice().last().unwrap().get_index();
            // Derive previous key if necessary
            if key_index > 0 {
                for _ in 0..key_index {
                    let _ = key_chain.issue_key(&mut db_tx, purpose).unwrap();
                }
            }
            key_chain.issue_key(&mut db_tx, purpose).unwrap()
        };
        assert_eq!(pk.get_derivation_path().to_string(), path_str.to_string());
        let sk = key_chain.get_private_key(master_key_chain.get_root_private_key(), &pk).unwrap();
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
            assert_eq!(leaf_keys.usage_state().get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state().get_last_used(), None);
        }

        let mut db_tx = db.transaction_rw(None).unwrap();

        key_chain.set_lookahead_size(&mut db_tx, 5).unwrap();
        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(19);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(leaf_keys.usage_state().get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state().get_last_used(), None);
        }

        key_chain.set_lookahead_size(&mut db_tx, 30).unwrap();
        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(29);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(leaf_keys.usage_state().get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state().get_last_used(), None);
        }

        key_chain.set_lookahead_size(&mut db_tx, 10).unwrap();
        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(29);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(leaf_keys.usage_state().get_last_issued(), None);
            assert_eq!(leaf_keys.usage_state().get_last_used(), None);
        }

        let mut issued_key = key_chain.issue_key(&mut db_tx, purpose).unwrap();

        // Mark the last key as used
        assert!(key_chain.mark_as_used(&mut db_tx, &issued_key).unwrap());

        {
            let leaf_keys = key_chain.get_leaf_key_chain(purpose);
            let last_derived_idx = ChildNumber::from_index_with_hardened_bit(29);
            assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
            assert_eq!(
                leaf_keys.usage_state().get_last_issued(),
                Some(ChildNumber::from_index_with_hardened_bit(0))
            );
            assert_eq!(
                leaf_keys.usage_state().get_last_used(),
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
                leaf_keys.usage_state().get_last_issued(),
                Some(ChildNumber::from_index_with_hardened_bit(10))
            );
            assert_eq!(
                leaf_keys.usage_state().get_last_used(),
                Some(ChildNumber::from_index_with_hardened_bit(10))
            );
        }
    }
}

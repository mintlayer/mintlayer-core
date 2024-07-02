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

use super::*;
use common::chain::config::{create_mainnet, create_unit_test_config};
use common::{address::pubkeyhash::PublicKeyHash, chain::Destination};
use crypto::key::extended::ExtendedPublicKey;
use crypto::key::hdkd::derivable::Derivable;
use crypto::key::hdkd::u31::U31;
use crypto::key::secp256k1::Secp256k1PublicKey;
use crypto::key::PublicKey;
use rstest::rstest;
use std::str::FromStr;
use std::sync::Arc;
use test_utils::assert_encoded_eq;
use wallet_storage::{
    DefaultBackend, Store, TransactionRwLocked, TransactionRwUnlocked, Transactional,
};
use wallet_types::seed_phrase::StoreSeedPhrase;
use wallet_types::{account_info::DEFAULT_ACCOUNT_INDEX, AccountInfo};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
    let chain_config = Arc::new(create_mainnet());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();
    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config,
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::Store,
    )
    .unwrap();

    let mut key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
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

    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();
    let path = DerivationPath::from_str(path_str).unwrap();
    // Derive expected key
    let pk = {
        let key_index = path.as_slice().last().unwrap().get_index();
        // Derive previous key if necessary
        if key_index.into_u32() > 0 {
            for _ in 0..key_index.into_u32() {
                let _ = key_chain.issue_key(&mut db_tx, purpose).unwrap();
            }
        }
        key_chain.issue_key(&mut db_tx, purpose).unwrap()
    };
    assert_eq!(pk.get_derivation_path().to_string(), path_str.to_string());
    let sk = key_chain.derive_private_key(&pk, &db_tx).unwrap();
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
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();
    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::Store,
    )
    .unwrap();
    let mut key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    db_tx.commit().unwrap();

    let id = key_chain.get_account_id();

    let mut db_tx = db.transaction_rw(None).unwrap();
    assert_eq!(key_chain.lookahead_size(), LOOKAHEAD_SIZE);

    // Issue new addresses until the lookahead size is reached
    let mut last_address = key_chain.issue_address(&mut db_tx, purpose).unwrap().1;
    for _ in 1..key_chain.lookahead_size() {
        last_address = key_chain.issue_address(&mut db_tx, purpose).unwrap().1;
    }
    assert_eq!(
        key_chain.issue_address(&mut db_tx, purpose),
        Err(KeyChainError::LookAheadExceeded)
    );
    db_tx.commit().unwrap();

    let account_info = AccountInfo::new(
        &chain_config,
        key_chain.account_index(),
        key_chain.account_public_key().clone(),
        key_chain.lookahead_size(),
        None,
    );

    drop(key_chain);

    let mut key_chain = AccountKeyChainImplSoftware::load_from_database(
        Arc::clone(&chain_config),
        &db.transaction_ro().unwrap(),
        &id,
        &account_info,
    )
    .unwrap();
    assert_eq!(key_chain.lookahead_size(), LOOKAHEAD_SIZE);
    assert_eq!(key_chain.get_leaf_key_chain(purpose).last_used(), None);
    assert_eq!(
        key_chain.get_leaf_key_chain(purpose).last_issued(),
        Some(U31::from_u32_with_msb(LOOKAHEAD_SIZE - 1).0)
    );

    let mut db_tx = db.transaction_rw(None).unwrap();

    assert_eq!(
        key_chain.issue_address(&mut db_tx, purpose),
        Err(KeyChainError::LookAheadExceeded)
    );

    if let Destination::PublicKeyHash(pkh) = last_address.into_object() {
        key_chain.mark_public_key_hash_as_used(&mut db_tx, &pkh).unwrap();
    } else {
        panic!("Address is not a public key hash destination");
    }

    // Should be able to issue more addresses
    for _ in 0..key_chain.lookahead_size() {
        let _address = key_chain.issue_address(&mut db_tx, purpose).unwrap();
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
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();
    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::Store,
    )
    .unwrap();
    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let id = key_chain.get_account_id();
    db_tx.commit().unwrap();

    let account_info = AccountInfo::new(
        &chain_config,
        key_chain.account_index(),
        key_chain.account_public_key().clone(),
        key_chain.lookahead_size(),
        None,
    );

    drop(key_chain);

    let mut key_chain = AccountKeyChainImplSoftware::load_from_database(
        chain_config,
        &db.transaction_ro().unwrap(),
        &id,
        &account_info,
    )
    .unwrap();

    {
        let leaf_keys = key_chain.get_leaf_key_chain(purpose);
        let last_derived_idx = ChildNumber::from_index_with_hardened_bit(19);
        assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
        assert_eq!(leaf_keys.usage_state().last_issued(), None);
        assert_eq!(leaf_keys.usage_state().last_used(), None);
    }

    let mut db_tx = db.transaction_rw(None).unwrap();

    let mut issued_key = key_chain.issue_key(&mut db_tx, purpose).unwrap();

    // Mark the last key as used
    assert!(key_chain
        .mark_public_key_as_used(&mut db_tx, &issued_key.clone().into_public_key())
        .unwrap());

    {
        let leaf_keys = key_chain.get_leaf_key_chain(purpose);
        let last_derived_idx = ChildNumber::from_index_with_hardened_bit(20);
        assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
        assert_eq!(
            leaf_keys.usage_state().last_issued(),
            Some(U31::from_u32(0).unwrap())
        );
        assert_eq!(
            leaf_keys.usage_state().last_used(),
            Some(U31::from_u32(0).unwrap())
        );
    }

    // Derive keys until lookahead
    while let Ok(k) = key_chain.issue_key(&mut db_tx, purpose) {
        issued_key = k;
    }

    // Mark the last key as used
    assert!(key_chain
        .mark_public_key_as_used(&mut db_tx, &issued_key.into_public_key())
        .unwrap());

    {
        let leaf_keys = key_chain.get_leaf_key_chain(purpose);
        let last_derived_idx = ChildNumber::from_index_with_hardened_bit(40);
        assert_eq!(leaf_keys.get_last_derived_index(), Some(last_derived_idx));
        assert_eq!(
            leaf_keys.usage_state().last_issued(),
            Some(U31::from_u32(20).unwrap())
        );
        assert_eq!(
            leaf_keys.usage_state().last_used(),
            Some(U31::from_u32(20).unwrap())
        );
    }
}

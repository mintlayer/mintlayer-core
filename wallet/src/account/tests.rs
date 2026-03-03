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
use crate::key_chain::{MasterKeyChain, LOOKAHEAD_SIZE};
use common::chain::config::create_regtest;
use crypto::key::hdkd::child_number::ChildNumber;
use wallet_storage::{DefaultBackend, Store, TransactionRwUnlocked, Transactional};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;
use wallet_types::seed_phrase::StoreSeedPhrase;
use wallet_types::KeyPurpose::{Change, ReceiveFunds};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn account_addresses() {
    let config = Arc::new(create_regtest());
    let mut db = Store::new(DefaultBackend::new_in_memory()).unwrap();
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();

    let mut account = Account::new(config, &mut db_tx, key_chain, None).unwrap();
    db_tx.commit().unwrap();

    let test_vec = vec![
        (ReceiveFunds, "rmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dypq388a"),
        (Change, "rmt1qyltm78pn55qyv6vngnk0nlh6m2rrjg5cs5p5xsm"),
        (ReceiveFunds, "rmt1q9jvqp9p8rzp2prmpa8y9vde7yrvlxgz3s54n787"),
    ];

    let mut db_tx = db.transaction_rw(None).unwrap();
    for (purpose, address_str) in test_vec {
        let address = account.get_new_address(&mut db_tx, purpose).unwrap().1;
        assert_eq!(address.as_str(), address_str);
    }
}

#[test]
fn account_addresses_lookahead() {
    let config = Arc::new(create_regtest());
    let mut db = Store::new(DefaultBackend::new_in_memory()).unwrap();
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(config, &mut db_tx, key_chain, None).unwrap();

    assert_eq!(
        account.key_chain.get_leaf_key_chain(ReceiveFunds).last_issued(),
        None
    );
    let expected_last_derived =
        ChildNumber::from_index_with_hardened_bit(account.key_chain.lookahead_size() - 1);
    assert_eq!(
        account.key_chain.get_leaf_key_chain(ReceiveFunds).get_last_derived_index(),
        Some(expected_last_derived)
    );

    // Issue a new address
    let _address = account.key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
    assert_eq!(
        account.key_chain.get_leaf_key_chain(ReceiveFunds).last_issued(),
        Some(U31::from_u32(0).unwrap())
    );
    assert_eq!(
        account.key_chain.get_leaf_key_chain(ReceiveFunds).get_last_derived_index(),
        Some(expected_last_derived)
    );
}

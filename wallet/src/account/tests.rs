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
use common::chain::output_value::OutputValue;
use common::chain::signature::verify_signature;
use common::chain::timelock::OutputTimeLock;
use common::chain::{GenBlock, Transaction, TxInput};
use common::primitives::amount::UnsignedIntType;
use common::primitives::{Amount, Id, H256};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{Rng, RngCore};
use rstest::rstest;
use std::ops::{Div, Mul, Sub};
use test_utils::random::{make_seedable_rng, Seed};
use wallet_storage::{DefaultBackend, Store, TransactionRwUnlocked, Transactional};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;
use wallet_types::seed_phrase::StoreSeedPhrase;
use wallet_types::KeyPurpose::{Change, ReceiveFunds};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn account_addresses() {
    let config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
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
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
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
    let mut account = Account::new(config.clone(), &mut db_tx, key_chain, None).unwrap();

    let amounts: Vec<Amount> = (0..(2 + rng.next_u32() % 5))
        .map(|_| Amount::from_atoms(rng.next_u32() as UnsignedIntType))
        .collect();

    let total_amount = amounts.iter().fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());

    let utxos: Vec<TxOutput> = amounts
        .iter()
        .map(|a| {
            let purpose = if rng.gen_bool(0.5) {
                ReceiveFunds
            } else {
                Change
            };

            TxOutput::Transfer(
                OutputValue::Coin(*a),
                account.get_new_address(&mut db_tx, purpose).unwrap().1.decode_object(),
            )
        })
        .collect();

    let inputs: Vec<TxInput> = utxos
        .iter()
        .map(|_txo| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(&mut rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(&mut rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();

    let dest_amount = total_amount.div(10).unwrap().mul(5).unwrap();
    let lock_amount = total_amount.div(10).unwrap().mul(1).unwrap();
    let burn_amount = total_amount.div(10).unwrap().mul(1).unwrap();
    let change_amount = total_amount.div(10).unwrap().mul(2).unwrap();
    let outputs_amounts_sum = [dest_amount, lock_amount, burn_amount, change_amount]
        .iter()
        .fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());
    let _fee_amount = total_amount.sub(outputs_amounts_sum).unwrap();

    let (_dest_prv, dest_pub) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::Coin(dest_amount),
            Destination::PublicKey(dest_pub),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(lock_amount),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForSeconds(rng.next_u64()),
        ),
        TxOutput::Burn(OutputValue::Coin(burn_amount)),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100)),
            account.get_new_address(&mut db_tx, Change).unwrap().1.decode_object(),
        ),
    ];

    let tx = Transaction::new(0, inputs, outputs).unwrap();

    let req = SendRequest::from_transaction(tx, utxos.clone(), &|_| None).unwrap();

    let sig_tx = account.sign_transaction_from_req(req, &db_tx).unwrap();

    let utxos_ref = utxos.iter().map(Some).collect::<Vec<_>>();

    for i in 0..sig_tx.inputs().len() {
        let destination =
            crate::get_tx_output_destination(utxos_ref[i].unwrap(), &|_| None).unwrap();
        verify_signature(&config, &destination, &sig_tx, &utxos_ref, i).unwrap();
    }
}

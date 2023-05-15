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
use crate::key_chain::MasterKeyChain;
use common::address::pubkeyhash::PublicKeyHash;
use common::chain::config::create_regtest;
use common::chain::signature::verify_signature;
use common::chain::timelock::OutputTimeLock;
use common::chain::tokens::OutputValue;
use common::chain::{GenBlock, Transaction, TxInput};
use common::primitives::amount::UnsignedIntType;
use common::primitives::{Amount, Id, H256};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{Rng, RngCore};
use rstest::rstest;
use std::ops::{Div, Mul, Sub};
use test_utils::random::{make_seedable_rng, Seed};
use wallet_storage::{DefaultBackend, Store, TransactionRw, Transactional};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;
use wallet_types::KeyPurpose::{Change, ReceiveFunds};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn account_addresses() {
    let config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw(None).unwrap();

    let master_key_chain =
        MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX)
        .unwrap();

    let mut account = Account::new(config, &mut db_tx, key_chain).unwrap();
    db_tx.commit().unwrap();

    let test_vec = vec![
        (ReceiveFunds, "rmt14qdg6kvlkpfwcw6zjc3dlxpj0g6ddknf54evpv"),
        (Change, "rmt1867l3cva9qprxny6yanula7k6scuj9xy9rv7m2"),
        (ReceiveFunds, "rmt1vnqqfgfccs2sg7c0feptrw03qm8ejq5vqqvpql"),
    ];

    let mut db_tx = db.transaction_rw(None).unwrap();
    for (purpose, address_str) in test_vec {
        let address = account.get_new_address(&mut db_tx, purpose).unwrap();
        assert_eq!(address.get(), address_str);
    }
}

#[test]
fn account_addresses_lookahead() {
    let config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw(None).unwrap();

    let master_key_chain =
        MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX)
        .unwrap();
    let mut account = Account::new(config, &mut db_tx, key_chain).unwrap();

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
    account.key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
    assert_eq!(
        account.key_chain.get_leaf_key_chain(ReceiveFunds).last_issued(),
        Some(ChildNumber::from_index_with_hardened_bit(0))
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
    let mut db_tx = db.transaction_rw(None).unwrap();

    let master_key_chain =
        MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX)
        .unwrap();
    let mut account = Account::new(config.clone(), &mut db_tx, key_chain).unwrap();

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
                Destination::Address(
                    PublicKeyHash::try_from(&account.get_new_address(&mut db_tx, purpose).unwrap())
                        .unwrap(),
                ),
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
            TxInput::new(source_id, rng.next_u32())
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
            Destination::Address(
                PublicKeyHash::try_from(&account.get_new_address(&mut db_tx, Change).unwrap())
                    .unwrap(),
            ),
        ),
    ];

    let tx = Transaction::new(0, inputs, outputs, 0).unwrap();

    let req = SendRequest::from_transaction(tx, utxos.clone());

    let sig_tx = account.sign_transaction(&req).unwrap();

    let utxos_ref = utxos.iter().collect::<Vec<_>>();

    for i in 0..sig_tx.inputs().len() {
        let destination = Account::get_tx_output_destination(utxos_ref[i]).unwrap();
        verify_signature(&config, destination, &sig_tx, &utxos_ref, i).unwrap();
    }
}

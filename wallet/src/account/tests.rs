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
use common::primitives::id::WithId;
use common::primitives::{Amount, Idable, H256};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{Rng, RngCore};
use rstest::rstest;
use std::ops::{Div, Mul, Sub};
use test_utils::random::{make_seedable_rng, Seed};
use wallet_storage::{DefaultBackend, Store, TransactionRo, TransactionRw, Transactional};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;
use wallet_types::KeyPurpose::{Change, ReceiveFunds};
use wallet_types::TxState;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn account_transactions() {
    let config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw(None).unwrap();

    let master_key_chain =
        MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

    let mut key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX)
        .unwrap();

    let address1 = key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
    let address2 = key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
    let pk3 = key_chain.issue_key(&mut db_tx, ReceiveFunds).unwrap();
    let pk4 = key_chain.issue_key(&mut db_tx, ReceiveFunds).unwrap();

    let mut account = Account::new(config.clone(), &mut db_tx, key_chain).unwrap();
    db_tx.commit().unwrap();

    let id = account.get_account_id();

    let txo1 = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        Destination::Address(PublicKeyHash::try_from(address1.data(&config).unwrap()).unwrap()),
    );
    let txo2 = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(2)),
        Destination::Address(PublicKeyHash::try_from(address2.data(&config).unwrap()).unwrap()),
    );
    let txo3 = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(3)),
        Destination::PublicKey(pk3.into_public_key()),
    );
    let txo4 = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(4)),
        Destination::PublicKey(pk4.into_public_key()),
    );

    let tx1 = WithId::new(Transaction::new(1, vec![], vec![txo1, txo2, txo3, txo4], 0).unwrap());
    let tx2 = WithId::new(Transaction::new(2, vec![], vec![], 0).unwrap());
    let tx3 = WithId::new(Transaction::new(3, vec![], vec![], 0).unwrap());
    let tx4 = WithId::new(Transaction::new(4, vec![], vec![], 0).unwrap());

    let block_id: Id<GenBlock> = H256::from_low_u64_le(123).into();

    let mut db_tx = db.transaction_rw(None).unwrap();
    account
        .add_transaction(&mut db_tx, tx1.clone(), TxState::Confirmed(block_id))
        .unwrap();
    account
        .add_transaction(&mut db_tx, tx2.clone(), TxState::Conflicted(block_id))
        .unwrap();
    account.add_transaction(&mut db_tx, tx3.clone(), TxState::InMempool).unwrap();
    account.add_transaction(&mut db_tx, tx4.clone(), TxState::Inactive).unwrap();
    db_tx.commit().unwrap();

    assert_eq!(id, account.get_account_id());
    assert_eq!(4, account.txs.len());
    assert_eq!(&tx1, account.txs.get(&tx1.get_id()).unwrap().tx());
    assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().tx());
    assert_eq!(&tx3, account.txs.get(&tx3.get_id()).unwrap().tx());
    assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().tx());

    // assert_eq!(4, account.utxo.len());

    drop(account);

    let db_tx = db.transaction_ro().unwrap();
    let mut account = Account::load_from_database(config.clone(), &db_tx, &id).unwrap();
    db_tx.close();

    assert_eq!(id, account.get_account_id());
    assert_eq!(4, account.txs.len());
    assert_eq!(&tx1, account.txs.get(&tx1.get_id()).unwrap().tx());
    assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().tx());
    assert_eq!(&tx3, account.txs.get(&tx3.get_id()).unwrap().tx());
    assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().tx());
    // assert_eq!(4, account.utxo.len());

    let mut db_tx = db.transaction_rw(None).unwrap();
    account.delete_transaction(&mut db_tx, tx1.get_id()).unwrap();
    account.delete_transaction(&mut db_tx, tx3.get_id()).unwrap();
    db_tx.commit().unwrap();

    assert_eq!(id, account.get_account_id());
    assert_eq!(2, account.txs.len());
    assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().tx());
    assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().tx());
    // assert_eq!(0, account.utxo.len());

    drop(account);

    let db_tx = db.transaction_ro().unwrap();
    let account = Account::load_from_database(config, &db_tx, &id).unwrap();
    db_tx.close();

    assert_eq!(id, account.get_account_id());
    assert_eq!(2, account.txs.len());
    assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().tx());
    assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().tx());
    // assert_eq!(0, account.utxo.len());
}

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

    assert_eq!(account.get_last_issued(ReceiveFunds), None);
    let expected_last_derived =
        ChildNumber::from_index_with_hardened_bit(account.key_chain.lookahead_size() - 1);
    assert_eq!(
        account.get_last_derived_index(ReceiveFunds),
        Some(expected_last_derived)
    );

    // Issue a new address
    account.key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
    assert_eq!(
        account.get_last_issued(ReceiveFunds),
        Some(ChildNumber::from_index_with_hardened_bit(0))
    );
    assert_eq!(
        account.get_last_derived_index(ReceiveFunds),
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

    let mut req = SendRequest::from_transaction(tx);
    // req.set_connected_tx_outputs(utxos.clone());

    account.complete_send_request(&mut req).unwrap();

    let sig_tx = req.get_signed_transaction().unwrap();

    let utxos_ref = utxos.iter().collect::<Vec<_>>();

    for i in 0..sig_tx.inputs().len() {
        let destination = Account::get_tx_output_destination(utxos_ref[i]).unwrap();
        verify_signature(&config, destination, &sig_tx, &utxos_ref, i).unwrap();
    }
}

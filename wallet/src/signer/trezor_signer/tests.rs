// Copyright (c) 2024 RBB S.r.l
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

use std::ops::{Add, Div, Mul, Sub};

use super::*;
use crate::destination_getters::{get_tx_output_destination, HtlcSpendingCondition};
use crate::key_chain::{MasterKeyChain, LOOKAHEAD_SIZE};
use crate::{Account, SendRequest};
use common::chain::config::create_regtest;
use common::chain::output_value::OutputValue;
use common::chain::signature::inputsig::arbitrary_message::produce_message_challenge;
use common::chain::timelock::OutputTimeLock;
use common::chain::tokens::TokenId;
use common::chain::{
    AccountNonce, AccountOutPoint, DelegationId, GenBlock, PoolId, Transaction, TxInput,
};
use common::primitives::{Amount, Id, H256};
use crypto::key::{KeyKind, PrivateKey};
use randomness::{Rng, RngCore};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use trezor_client::find_devices;
use wallet_storage::{DefaultBackend, Store, Transactional};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;
use wallet_types::seed_phrase::StoreSeedPhrase;
use wallet_types::KeyPurpose::{Change, ReceiveFunds};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_message(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(chain_config.clone(), &mut db_tx, key_chain, None).unwrap();

    let destination = account.get_new_address(&mut db_tx, ReceiveFunds).unwrap().1.into_object();
    let mut devices = find_devices(false);
    assert!(!devices.is_empty());
    let client = devices.pop().unwrap().connect().unwrap();

    let mut signer = TrezorSigner::new(chain_config.clone(), Arc::new(Mutex::new(client)));
    let message = vec![rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()];
    let res = signer
        .sign_challenge(
            message.clone(),
            destination.clone(),
            account.key_chain(),
            &db_tx,
        )
        .unwrap();

    let message_challenge = produce_message_challenge(&message);
    res.verify_signature(&chain_config, &destination, &message_challenge).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(chain_config.clone(), &mut db_tx, key_chain, None).unwrap();

    let amounts: Vec<Amount> = (0..3) //(0..(2 + rng.next_u32() % 5))
        // .map(|_| Amount::from_atoms(rng.next_u32() as UnsignedIntType))
        .map(|_| Amount::from_atoms(1))
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
                account.get_new_address(&mut db_tx, purpose).unwrap().1.into_object(),
            )
        })
        .collect();

    let inputs: Vec<TxInput> = (0..utxos.len())
        .map(|_| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(&mut rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(&mut rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();

    let acc_inputs = vec![
        TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(1),
            AccountSpending::DelegationBalance(
                DelegationId::new(H256::random_using(&mut rng)),
                Amount::from_atoms(rng.next_u32() as u128),
            ),
        )),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::UnmintTokens(TokenId::new(H256::random_using(&mut rng))),
        ),
    ];
    let acc_dests: Vec<Destination> = acc_inputs
        .iter()
        .map(|_| {
            let purpose = if rng.gen_bool(0.5) {
                ReceiveFunds
            } else {
                Change
            };

            account.get_new_address(&mut db_tx, purpose).unwrap().1.into_object()
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
            OutputValue::Coin(Amount::from_atoms(100_000_000_000)),
            account.get_new_address(&mut db_tx, Change).unwrap().1.into_object(),
        ),
        TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            PoolId::new(H256::random_using(&mut rng)),
        ),
        TxOutput::DelegateStaking(
            Amount::from_atoms(200),
            DelegationId::new(H256::random_using(&mut rng)),
        ),
    ];

    let req = SendRequest::new()
        .with_inputs(inputs.clone().into_iter().zip(utxos.clone()), &|_| None)
        .unwrap()
        .with_inputs_and_destinations(acc_inputs.into_iter().zip(acc_dests.clone()))
        .with_outputs(outputs);
    let ptx = req.into_partially_signed_tx(&BTreeMap::default()).unwrap();

    let mut devices = find_devices(false);
    assert!(!devices.is_empty());
    let client = devices.pop().unwrap().connect().unwrap();

    let mut signer = TrezorSigner::new(chain_config.clone(), Arc::new(Mutex::new(client)));
    let (ptx, _, _) = signer.sign_tx(ptx, account.key_chain(), &db_tx).unwrap();

    eprintln!("num inputs in tx: {} {:?}", inputs.len(), ptx.witnesses());
    assert!(ptx.all_signatures_available());

    let sig_tx = ptx.into_signed_tx().unwrap();

    let utxos_ref =
        utxos.iter().map(Some).chain(acc_dests.iter().map(|_| None)).collect::<Vec<_>>();

    for i in 0..sig_tx.inputs().len() {
        let destination = get_tx_output_destination(
            utxos_ref[i].unwrap(),
            &|_| None,
            HtlcSpendingCondition::Skip,
        )
        .unwrap();

        tx_verifier::input_check::signature_only_check::verify_tx_signature(
            &chain_config,
            &destination,
            &sig_tx,
            &utxos_ref,
            i,
        )
        .unwrap();
    }
}

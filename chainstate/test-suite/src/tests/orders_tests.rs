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

use chainstate::ConnectTransactionError;
use chainstate_storage::Transactional;
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    chain::{
        make_order_id,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            DestinationSigError,
        },
        tokens::{TokenId, TokenIssuance},
        AccountCommand, AccountNonce, Destination, OrderData, SignedTransaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{Amount, Idable},
};
use crypto::key::{KeyKind, PrivateKey};
use orders_accounting::OrdersAccountingDB;
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::{
    nft_utils::random_token_issuance_v1,
    random::{make_seedable_rng, Seed},
};
use tx_verifier::error::{InputCheckError, ScriptError};

use crate::tests::helpers::{issue_token_from_block, mint_tokens_in_block};

fn issue_and_mint_token(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> (TokenId, UtxoOutPoint, UtxoOutPoint) {
    let genesis_block_id = tf.best_block_id();
    let issuance = TokenIssuance::V1(random_token_issuance_v1(
        tf.chain_config(),
        Destination::AnyoneCanSpend,
        rng,
    ));
    let (token_id, _, utxo_with_change) = issue_token_from_block(
        rng,
        tf,
        genesis_block_id,
        UtxoOutPoint::new(genesis_block_id.into(), 0),
        issuance,
    );

    let best_block_id = tf.best_block_id();
    let (_, mint_tx_id) = mint_tokens_in_block(
        rng,
        tf,
        best_block_id,
        utxo_with_change,
        token_id,
        Amount::from_atoms(100_000),
        true,
    );

    (
        token_id,
        UtxoOutPoint::new(mint_tx_id.into(), 0),
        UtxoOutPoint::new(mint_tx_id.into(), 1),
    )
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_check_storage(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
        assert_eq!(
            Some(ask_amount),
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some(give_amount),
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_two_orders_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            .build();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::StateUpdateFailed(
                    chainstate::ConnectTransactionError::OrdersAccountingError(
                        orders_accounting::Error::OrderAlreadyExists(order_id)
                    )
                )
            )
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn withdraw_order_check_storage(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::WithdrawOrder(order_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(None, tf.chainstate.get_order_data(&order_id).unwrap());
        assert_eq!(
            None,
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            None,
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fill_order_check_storage(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, coins_outpoint) = issue_and_mint_token(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_value = OutputValue::Coin(Amount::from_atoms(
            rng.gen_range(1..ask_amount.into_atoms()),
        ));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, &fill_value).unwrap()
        };
        let left_to_fill = (ask_amount - fill_value.amount()).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(
                TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(order_id, fill_value, Destination::AnyoneCanSpend),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(left_to_fill),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let partial_fill_tx_id = tx.transaction().get_id();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
        assert_eq!(
            Some(left_to_fill),
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some((give_amount - filled_amount).unwrap()),
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );

        // Fill the rest of the order
        let fill_value = OutputValue::Coin(left_to_fill);
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, &fill_value).unwrap()
        };

        let tx = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(partial_fill_tx_id.into(), 1).into(),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::AccountCommand(
                    AccountNonce::new(1),
                    AccountCommand::FillOrder(order_id, fill_value, Destination::AnyoneCanSpend),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(None, tf.chainstate.get_order_data(&order_id).unwrap());
        assert_eq!(
            None,
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            None,
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn withdraw_order_check_signature(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (order_sk, order_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let (token_id, tokens_outpoint, _) = issue_and_mint_token(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let order_data = OrderData::new(
            Destination::PublicKey(order_pk.clone()),
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // try withdraw without signature
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::AccountCommand(
                        AccountNonce::new(0),
                        AccountCommand::WithdrawOrder(order_id),
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, give_amount),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                        InputCheckError::new(
                            0,
                            ScriptError::Signature(DestinationSigError::SignatureNotFound)
                        )
                    ))
                )
            )
        }

        // try withdraw with wrong signature
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::AccountCommand(
                        AccountNonce::new(0),
                        AccountCommand::WithdrawOrder(order_id),
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, give_amount),
                    Destination::AnyoneCanSpend,
                ))
                .build();

            let inputs_utxos: Vec<Option<TxOutput>> = vec![None];
            let inputs_utxos_refs =
                inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &inputs_utxos_refs,
                0,
                &mut rng,
            )
            .unwrap();

            let tx = SignedTransaction::new(
                tx.take_transaction(),
                vec![InputWitness::Standard(account_sig)],
            )
            .unwrap();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                        InputCheckError::new(
                            0,
                            ScriptError::Signature(
                                DestinationSigError::SignatureVerificationFailed
                            )
                        )
                    ))
                )
            )
        }

        // valid case
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::WithdrawOrder(order_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let inputs_utxos: Vec<Option<TxOutput>> = vec![None];
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
            &order_sk,
            Default::default(),
            Destination::PublicKey(order_pk),
            &tx,
            &inputs_utxos_refs,
            0,
            &mut rng,
        )
        .unwrap();

        let tx = SignedTransaction::new(
            tx.take_transaction(),
            vec![InputWitness::Standard(account_sig)],
        )
        .unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    });
}

// Create a chain with an order which is filled partially.
// Reorg from a point before the order was created, so that after reorg storage has no information on the order
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_before_create(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, coins_outpoint) = issue_and_mint_token(&mut rng, &mut tf);
        let reorg_common_ancestor = tf.best_block_id();

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_value = OutputValue::Coin(Amount::from_atoms(
            rng.gen_range(1..ask_amount.into_atoms()),
        ));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, &fill_value).unwrap()
        };
        let left_to_fill = (ask_amount - fill_value.amount()).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(
                TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(order_id, fill_value, Destination::AnyoneCanSpend),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(left_to_fill),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
        assert_eq!(
            Some(left_to_fill),
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some((give_amount - filled_amount).unwrap()),
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );

        // Create alternative chain and trigger the reorg
        let new_best_block = tf.create_chain(&reorg_common_ancestor, 3, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), new_best_block);

        assert_eq!(None, tf.chainstate.get_order_data(&order_id).unwrap());
        assert_eq!(
            None,
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            None,
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );
    });
}

// Create a chain with an order which is filled partially and then withdrawn.
// Reorg from a point after the order was created, so that after reorg storage has original information on the order
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_after_create(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, coins_outpoint) = issue_and_mint_token(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::AnyoneCanTake(order_data.clone()))
            // transfer output just to be able to spend something in alternative branch
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
        let reorg_common_ancestor = tf.best_block_id();

        // Fill the order partially
        let fill_value = OutputValue::Coin(Amount::from_atoms(
            rng.gen_range(1..ask_amount.into_atoms()),
        ));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, &fill_value).unwrap()
        };
        let left_to_fill = (ask_amount - fill_value.amount()).unwrap();

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
                    .add_input(
                        TxInput::AccountCommand(
                            AccountNonce::new(0),
                            AccountCommand::FillOrder(
                                order_id,
                                fill_value,
                                Destination::AnyoneCanSpend,
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, filled_amount),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(left_to_fill),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::AccountCommand(
                            AccountNonce::new(1),
                            AccountCommand::WithdrawOrder(order_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(None, tf.chainstate.get_order_data(&order_id).unwrap());
        assert_eq!(
            None,
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            None,
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );

        // Create alternative chain and trigger the reorg
        let new_best_block = tf.create_chain(&reorg_common_ancestor, 3, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), new_best_block);

        assert_eq!(
            Some(order_data.clone()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
        assert_eq!(
            Some(order_data.ask().amount()),
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some(order_data.give().amount()),
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );
    });
}

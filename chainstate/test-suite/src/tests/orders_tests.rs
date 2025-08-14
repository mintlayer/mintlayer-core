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

use std::borrow::Cow;

use rstest::rstest;

use chainstate::{
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError,
};
use chainstate_test_framework::{
    helpers::{calculate_fill_order, issue_and_mint_random_token_from_best_block},
    output_value_amount, TestFramework, TransactionBuilder,
};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        make_order_id, make_token_id,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::{input_commitments::SighashInputCommitment, sighashtype::SigHashType},
            verify_signature, DestinationSigError, EvaluatedInputWitness,
        },
        tokens::{IsTokenFreezable, TokenId, TokenTotalSupply},
        AccountCommand, AccountNonce, ChainstateUpgradeBuilder, Destination, OrderAccountCommand,
        OrderData, OrderId, OrdersVersion, SignedTransaction, Transaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Idable, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use logging::log;
use randomness::{CryptoRng, Rng, SliceRandom};
use test_utils::{
    random::{gen_random_bytes, make_seedable_rng, Seed},
    token_utils::random_nft_issuance,
};
use tx_verifier::{
    error::{InputCheckError, InputCheckErrorPayload, ScriptError, TranslationError},
    input_check::signature_only_check::verify_tx_signature,
    CheckTransactionError,
};

fn create_test_framework_with_orders(
    rng: &mut (impl Rng + CryptoRng),
    orders_version: OrdersVersion,
) -> TestFramework {
    TestFramework::builder(rng)
        .with_chain_config(
            common::chain::config::Builder::test_chain()
                .chainstate_upgrades(
                    common::chain::NetUpgrades::initialize(vec![(
                        BlockHeight::zero(),
                        ChainstateUpgradeBuilder::latest().orders_version(orders_version).build(),
                    )])
                    .unwrap(),
                )
                .build(),
        )
        .build()
}

fn issue_and_mint_token_from_genesis(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> (TokenId, UtxoOutPoint, UtxoOutPoint) {
    let to_mint = Amount::from_atoms(rng.gen_range(100..100_000_000));
    issue_and_mint_token_amount_from_genesis(rng, tf, to_mint)
}

fn issue_and_mint_token_amount_from_genesis(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    to_mint: Amount,
) -> (TokenId, UtxoOutPoint, UtxoOutPoint) {
    let genesis_block_id = tf.genesis().get_id();
    let utxo = UtxoOutPoint::new(genesis_block_id.into(), 0);

    issue_and_mint_random_token_from_best_block(
        rng,
        tf,
        utxo,
        to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    )
}

fn issue_and_mint_token_amount_from_best_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    utxo_outpoint: UtxoOutPoint,
    to_mint: Amount,
) -> (TokenId, UtxoOutPoint, UtxoOutPoint) {
    issue_and_mint_random_token_from_best_block(
        rng,
        tf,
        utxo_outpoint,
        to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    )
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_check_storage(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data.into()),
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
fn create_two_identical_orders_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();
        let half_tokens_circulating_supply = (tokens_circulating_supply / 2).unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=half_tokens_circulating_supply.into_atoms()));
        let order_data = Box::new(OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        ));

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(order_data.clone()))
            .add_output(TxOutput::CreateOrder(order_data))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::IOPolicyError(
                    chainstate::IOPolicyError::MultipleOrdersCreated,
                    tx_id.into()
                ))
            )
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_two_different_orders_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();
        let half_tokens_circulating_supply = (tokens_circulating_supply / 2).unwrap();

        let amount1 = Amount::from_atoms(rng.gen_range(1u128..1000));
        let amount2 =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data_1 = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(amount1),
            OutputValue::TokenV1(token_id, half_tokens_circulating_supply),
        );

        let order_data_2 = OrderData::new(
            Destination::PublicKeyHash(PublicKeyHash::random()),
            OutputValue::Coin(amount2),
            OutputValue::TokenV1(token_id, half_tokens_circulating_supply),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data_1)))
            .add_output(TxOutput::CreateOrder(Box::new(order_data_2)))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::IOPolicyError(
                    chainstate::IOPolicyError::MultipleOrdersCreated,
                    tx_id.into()
                ))
            )
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_two_identical_orders_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = Box::new(OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        ));

        let tx1 = TransactionBuilder::new()
            .add_input(
                tokens_outpoint.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::CreateOrder(order_data.clone()))
            .build();
        let tx2 = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(order_data))
            .build();
        let block = tf.make_block_builder().with_transactions(vec![tx1, tx2]).build(&mut rng);
        let block_id = block.get_id();
        let result = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::CheckBlockFailed(
                    chainstate::CheckBlockError::CheckTransactionFailed(
                        chainstate::CheckBlockTransactionsError::DuplicateInputInBlock(block_id)
                    )
                )
            )
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_check_currencies(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));

        // Check coins for coins trade
        {
            let order_data = OrderData::new(
                Destination::AnyoneCanSpend,
                OutputValue::Coin(ask_amount),
                OutputValue::Coin(give_amount),
            );

            let tx = TransactionBuilder::new()
                .add_input(
                    tokens_outpoint.clone().into(),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::CheckBlockFailed(
                        chainstate::CheckBlockError::CheckTransactionFailed(
                            chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                tx_verifier::CheckTransactionError::OrdersCurrenciesMustBeDifferent(
                                    tx_id
                                )
                            )
                        )
                    )
                )
            );
        }

        // Check tokens for tokens trade
        {
            let order_data = OrderData::new(
                Destination::AnyoneCanSpend,
                OutputValue::TokenV1(token_id, ask_amount),
                OutputValue::TokenV1(token_id, give_amount),
            );

            let tx = TransactionBuilder::new()
                .add_input(
                    tokens_outpoint.clone().into(),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::CheckBlockFailed(
                        chainstate::CheckBlockError::CheckTransactionFailed(
                            chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                tx_verifier::CheckTransactionError::OrdersCurrenciesMustBeDifferent(
                                    tx_id
                                )
                            )
                        )
                    )
                )
            );
        }

        // Trade tokens for coins
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_tokens_for_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id_1, _, coins_outpoint) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);

        let token_2_mint_amount = Amount::from_atoms(rng.gen_range(100..100_000_000));
        let (token_id_2, tokens_outpoint_2, _) = issue_and_mint_token_amount_from_best_block(
            &mut rng,
            &mut tf,
            coins_outpoint,
            token_2_mint_amount,
        );

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..token_2_mint_amount.into_atoms()));

        // Trade tokens for coins
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(token_id_1, ask_amount),
            OutputValue::TokenV1(token_id_2, give_amount),
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tokens_outpoint_2.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn conclude_order_check_storage(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let make_conclude_input = |order_id| match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::ConcludeOrder(order_id),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
            }
        };

        // Try conclude nonexisting order
        {
            let random_order_id = OrderId::new(H256::random_using(&mut rng));

            let tx = TransactionBuilder::new()
                .add_input(
                    make_conclude_input(random_order_id),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, give_amount),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let error = tf
                .make_block_builder()
                .add_transaction(tx)
                .build_and_process(&mut rng)
                .unwrap_err();

            assert_eq!(
                error,
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(
                        ConnectTransactionError::ConstrainedValueAccumulatorError(
                            orders_accounting::Error::OrderDataNotFound(random_order_id).into(),
                            tx_id.into()
                        )
                    )
                )
            );
        }

        let tx = TransactionBuilder::new()
            .add_input(
                make_conclude_input(order_id),
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
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn conclude_order_multiple_txs(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let tx_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::ConcludeOrder(order_id),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
            }
        };
        let tx1 = TransactionBuilder::new()
            .add_input(tx_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let tx_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::ConcludeOrder(order_id),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
            }
        };
        let tx2 = TransactionBuilder::new()
            .add_input(tx_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx2_id = tx2.transaction().get_id();

        let block = tf.make_block_builder().with_transactions(vec![tx1, tx2]).build(&mut rng);
        let block_id = block.get_id();
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        match version {
            OrdersVersion::V0 => {
                assert_eq!(
                    res.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::StateUpdateFailed(
                            ConnectTransactionError::ConstrainedValueAccumulatorError(
                                orders_accounting::Error::OrderDataNotFound(order_id).into(),
                                tx2_id.into()
                            )
                        )
                    )
                );
            }
            OrdersVersion::V1 => {
                assert_eq!(
                    res.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            chainstate::CheckBlockError::CheckTransactionFailed(
                                CheckBlockTransactionsError::DuplicateInputInBlock(block_id)
                            )
                        )
                    )
                );
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_check_storage(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(10u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..ask_amount.into_atoms()));
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, version);
        let left_to_fill = (ask_amount - fill_amount).unwrap();

        let fill_order_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_order_input, InputWitness::NoSignature(None))
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
            Some(order_data.clone().into()),
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
        let filled_amount = calculate_fill_order(&tf, &order_id, left_to_fill, version);

        let fill_order_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::FillOrder(order_id, left_to_fill, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, left_to_fill))
            }
        };

        let tx = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(partial_fill_tx_id.into(), 1).into(),
                InputWitness::NoSignature(None),
            )
            .add_input(fill_order_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data.into()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
        assert_eq!(
            None,
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        match version {
            OrdersVersion::V0 => {
                assert_eq!(
                    None,
                    tf.chainstate.get_order_give_balance(&order_id).unwrap()
                );
            }
            OrdersVersion::V1 => {
                let filled1 =
                    (give_amount.into_atoms() * fill_amount.into_atoms()) / ask_amount.into_atoms();
                let filled2 = (give_amount.into_atoms() * left_to_fill.into_atoms())
                    / ask_amount.into_atoms();
                let remainder = (give_amount - Amount::from_atoms(filled1 + filled2))
                    .filter(|v| *v != Amount::ZERO);
                assert_eq!(
                    remainder,
                    tf.chainstate.get_order_give_balance(&order_id).unwrap()
                );
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_partially_then_conclude(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..=ask_amount.into_atoms()));
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, version);

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        {
            // Try overspend give in conclude order
            let conclude_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(1),
                    AccountCommand::ConcludeOrder(order_id),
                ),
                OrdersVersion::V1 => {
                    TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
                }
            };
            let tx = TransactionBuilder::new()
                .add_input(conclude_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(
                        token_id,
                        (give_amount - filled_amount)
                            .and_then(|v| v + Amount::from_atoms(1))
                            .unwrap(),
                    ),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(fill_amount),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::TokenId(token_id)
                        ),
                        tx_id.into()
                    )
                ))
            );
        }

        {
            // Try overspend ask in conclude order
            let conclude_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(1),
                    AccountCommand::ConcludeOrder(order_id),
                ),
                OrdersVersion::V1 => {
                    TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
                }
            };
            let tx = TransactionBuilder::new()
                .add_input(conclude_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, (give_amount - filled_amount).unwrap()),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin((fill_amount + Amount::from_atoms(1)).unwrap()),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::Coin
                        ),
                        tx_id.into()
                    )
                ))
            );
        }

        // conclude the order
        let conclude_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::ConcludeOrder(order_id),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(conclude_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, (give_amount - filled_amount).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(fill_amount),
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

        {
            // Try filling concluded order
            let fill_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(2),
                    AccountCommand::FillOrder(
                        order_id,
                        (give_amount - filled_amount).unwrap(),
                        Destination::AnyoneCanSpend,
                    ),
                ),
                OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id,
                    (give_amount - filled_amount).unwrap(),
                )),
            };
            let tx = TransactionBuilder::new()
                .add_input(fill_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, filled_amount),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            // Note: In V1, zero fills are not allowed. Since the zero fill check happens during
            // an earlier stage (in tx_verifier::check_transaction), we'll hit AttemptToFillOrderWithZero
            // first in this case.
            if give_amount != filled_amount || version == OrdersVersion::V0 {
                assert_eq!(
                    res.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::StateUpdateFailed(
                            ConnectTransactionError::ConstrainedValueAccumulatorError(
                                constraints_value_accumulator::Error::OrdersAccountingError(
                                    orders_accounting::Error::OrderDataNotFound(order_id)
                                ),
                                tx_id.into()
                            )
                        )
                    )
                );
            } else {
                assert_eq!(
                    res.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            CheckBlockError::CheckTransactionFailed(
                                CheckBlockTransactionsError::CheckTransactionError(
                                    CheckTransactionError::AttemptToFillOrderWithZero(
                                        order_id, tx_id
                                    )
                                )
                            )
                        )
                    )
                );
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn try_overbid_order_in_multiple_txs(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(2u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ask_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ask_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        let tx_id = tx.transaction().get_id();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, ask_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, ask_amount))
            }
        };
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_input(fill_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::FillOrder(
                    order_id,
                    Amount::from_atoms(1),
                    Destination::AnyoneCanSpend,
                ),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                Amount::from_atoms(1),
            )),
        };
        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_id.into(), 2),
                InputWitness::NoSignature(None),
            )
            .add_input(fill_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx2_id = tx2.transaction().get_id();

        let res = tf
            .make_block_builder()
            .with_transactions(vec![tx1, tx2])
            .build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        orders_accounting::Error::OrderOverbid(
                            order_id,
                            Amount::ZERO,
                            Amount::from_atoms(1)
                        )
                        .into(),
                        tx2_id.into()
                    )
                )
            )
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_completely_then_conclude(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        {
            // Try overspend complete fill order
            let fill_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(order_id, ask_amount, Destination::AnyoneCanSpend),
                ),
                OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id, ask_amount,
                )),
            };
            let tx = TransactionBuilder::new()
                .add_input(
                    coins_outpoint.clone().into(),
                    InputWitness::NoSignature(None),
                )
                .add_input(fill_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, (give_amount + Amount::from_atoms(1)).unwrap()),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::TokenId(token_id)
                        ),
                        tx_id.into()
                    )
                ))
            );
        }

        {
            // Try overbid complete fill order
            let fill_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(
                        order_id,
                        (ask_amount + Amount::from_atoms(1)).unwrap(),
                        Destination::AnyoneCanSpend,
                    ),
                ),
                OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id,
                    (ask_amount + Amount::from_atoms(1)).unwrap(),
                )),
            };
            let tx = TransactionBuilder::new()
                .add_input(
                    coins_outpoint.clone().into(),
                    InputWitness::NoSignature(None),
                )
                .add_input(fill_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, give_amount),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(
                res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(
                        ConnectTransactionError::ConstrainedValueAccumulatorError(
                            orders_accounting::Error::OrderOverbid(
                                order_id,
                                ask_amount,
                                (ask_amount + Amount::from_atoms(1)).unwrap()
                            )
                            .into(),
                            tx_id.into()
                        )
                    )
                )
            );
        }

        // Fill the order completely
        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, ask_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, ask_amount))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        {
            // Try overspend conclude order
            let conclude_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(1),
                    AccountCommand::ConcludeOrder(order_id),
                ),
                OrdersVersion::V1 => {
                    TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
                }
            };
            let tx = TransactionBuilder::new()
                .add_input(conclude_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin((ask_amount + Amount::from_atoms(1)).unwrap()),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::Coin
                        ),
                        tx_id.into()
                    )
                ))
            );
        }

        // conclude the order
        let conclude_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::ConcludeOrder(order_id),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(conclude_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ask_amount),
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
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn conclude_order_check_signature(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (order_sk, order_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let initially_asked = OutputValue::Coin(Amount::from_atoms(rng.gen_range(1u128..1000)));
        let initially_given = OutputValue::TokenV1(
            token_id,
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms())),
        );
        let order_data = OrderData::new(
            Destination::PublicKey(order_pk.clone()),
            initially_asked.clone(),
            initially_given.clone(),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let conclude_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::ConcludeOrder(order_id),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(conclude_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                initially_given.clone(),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let input_commitments = tf.make_sighash_input_commitments_for_transaction_inputs(
            tx.inputs(),
            tf.next_block_height(),
        );

        // try conclude without signature
        {
            let result =
                tf.make_block_builder().add_transaction(tx.clone()).build_and_process(&mut rng);

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

        // try conclude with wrong signature
        {
            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            let tx = SignedTransaction::new(
                tx.transaction().clone(),
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
        {
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &order_sk,
                Default::default(),
                Destination::PublicKey(order_pk),
                &tx,
                &input_commitments,
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
        }
    });
}

// Create a chain with an order which is filled partially.
// Reorg from a point before the order was created, so that after reorg storage has no information on the order
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn reorg_before_create(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();
        let reorg_common_ancestor = tf.best_block_id();

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let create_order_tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(create_order_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(create_order_tx.clone())
            .build_and_process(&mut rng)
            .unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..ask_amount.into_atoms()));
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, version);
        let left_to_fill = (ask_amount - fill_amount).unwrap();

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount))
            }
        };
        let fill_order_tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(left_to_fill),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder()
            .add_transaction(fill_order_tx.clone())
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            Some(order_data.clone().into()),
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
        let new_best_block =
            tf.create_chain_with_empty_blocks(&reorg_common_ancestor, 3, &mut rng).unwrap();
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

        // Reapply txs again
        tf.make_block_builder()
            .with_transactions(vec![create_order_tx, fill_order_tx])
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            Some(order_data.into()),
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
    });
}

// Create a chain with an order which is filled partially and then concluded.
// Reorg from a point after the order was created, so that after reorg storage has original information on the order
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn reorg_after_create(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            // transfer output just to be able to spend something in alternative branch
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
        let reorg_common_ancestor = tf.best_block_id();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..ask_amount.into_atoms()));
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, version);
        let left_to_fill = (ask_amount - fill_amount).unwrap();

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount))
            }
        };
        let fill_order_tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(left_to_fill),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder()
            .add_transaction(fill_order_tx.clone())
            .build_and_process(&mut rng)
            .unwrap();

        let conclude_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::ConcludeOrder(order_id),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
            }
        };
        let conclude_order_tx = TransactionBuilder::new()
            .add_input(conclude_input, InputWitness::NoSignature(None))
            .build();
        tf.make_block_builder()
            .add_transaction(conclude_order_tx.clone())
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
        let new_best_block =
            tf.create_chain_with_empty_blocks(&reorg_common_ancestor, 3, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), new_best_block);

        assert_eq!(
            Some(output_value_amount(order_data.ask())),
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some(output_value_amount(order_data.give())),
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some(order_data.into()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );

        // Reapply txs again
        tf.make_block_builder()
            .with_transactions(vec![fill_order_tx, conclude_order_tx])
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
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_activation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        // activate orders at height 4 (genesis + issue block + mint block + empty block)
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .orders_activated(common::chain::OrdersActivated::No)
                                    .build(),
                            ),
                            (
                                BlockHeight::new(4),
                                ChainstateUpgradeBuilder::latest()
                                    .orders_activated(common::chain::OrdersActivated::Yes)
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let order_data = Box::new(OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(Amount::from_atoms(rng.gen_range(1u128..1000))),
            OutputValue::TokenV1(
                token_id,
                Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms())),
            ),
        ));

        // Try to produce order output before activation, check an error
        let tx = TransactionBuilder::new()
            .add_input(
                tokens_outpoint.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::CreateOrder(order_data.clone()))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::CheckBlockFailed(
                    chainstate::CheckBlockError::CheckTransactionFailed(
                        chainstate::CheckBlockTransactionsError::CheckTransactionError(
                            tx_verifier::CheckTransactionError::OrdersAreNotActivated(tx_id)
                        )
                    )
                )
            )
        );

        // produce an empty block
        tf.make_block_builder().build_and_process(&mut rng).unwrap();

        // now it should be possible to use order output
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::CreateOrder(order_data))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn create_order_with_nft(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let genesis_input = TxInput::from_utxo(tf.genesis().get_id().into(), 0);
        let token_id = make_token_id(
            tf.chain_config(),
            tf.next_block_height(),
            &[genesis_input.clone()],
        )
        .unwrap();
        let nft_issuance = random_nft_issuance(tf.chain_config(), &mut rng);
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));

        // Issue an NFT
        let issue_nft_tx = TransactionBuilder::new()
            .add_input(genesis_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(nft_issuance.into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ask_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issue_nft_tx_id = issue_nft_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(issue_nft_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order selling NFT for coins
        let give_amount = Amount::from_atoms(1);
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let nft_outpoint = UtxoOutPoint::new(issue_nft_tx_id.into(), 0);

        let tx = TransactionBuilder::new()
            .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data.clone().into()),
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

        // Try get 2 nfts out of order
        {
            let fill_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(order_id, ask_amount, Destination::AnyoneCanSpend),
                ),
                OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id, ask_amount,
                )),
            };
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(issue_nft_tx_id.into(), 1),
                    InputWitness::NoSignature(None),
                )
                .add_input(fill_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, Amount::from_atoms(2)),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::TokenId(token_id)
                        ),
                        tx_id.into()
                    )
                ))
            );
        }

        // Fill order
        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, ask_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, ask_amount))
            }
        };
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issue_nft_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(fill_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            Some(order_data.into()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
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
fn partially_fill_order_with_nft_v0(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .orders_version(OrdersVersion::V0)
                                .build(),
                        )])
                        .unwrap(),
                    )
                    .build(),
            )
            .build();

        let genesis_input = TxInput::from_utxo(tf.genesis().get_id().into(), 0);
        let token_id = make_token_id(
            tf.chain_config(),
            tf.next_block_height(),
            &[genesis_input.clone()],
        )
        .unwrap();
        let nft_issuance = random_nft_issuance(tf.chain_config(), &mut rng);
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));

        // Issue an NFT
        let issue_nft_tx = TransactionBuilder::new()
            .add_input(genesis_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(nft_issuance.into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ask_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issue_nft_tx_id = issue_nft_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(issue_nft_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order selling NFT for coins
        let give_amount = Amount::from_atoms(1);
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let nft_outpoint = UtxoOutPoint::new(issue_nft_tx_id.into(), 0);
        let tx = TransactionBuilder::new()
            .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data.clone().into()),
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

        // Try get an nft out of order with 1 atom less
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(issue_nft_tx_id.into(), 1),
                    InputWitness::NoSignature(None),
                )
                .add_input(
                    TxInput::AccountCommand(
                        AccountNonce::new(0),
                        AccountCommand::FillOrder(
                            order_id,
                            (ask_amount - Amount::from_atoms(1)).unwrap(),
                            Destination::AnyoneCanSpend,
                        ),
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
            assert_eq!(result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::TokenId(token_id)
                        ),
                        tx_id.into()
                    )
                ))
            );
        }

        // Fill order with 1 atom less, getting 0 nfts
        let partially_fill_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issue_nft_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(
                        order_id,
                        (ask_amount - Amount::from_atoms(1)).unwrap(),
                        Destination::AnyoneCanSpend,
                    ),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(0)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let partially_fill_tx_id = partially_fill_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(partially_fill_tx)
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            Some(order_data.clone().into()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
        assert_eq!(
            Some(Amount::from_atoms(1)),
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some(give_amount),
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );

        // Fill order only with proper amount spent
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(partially_fill_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::AccountCommand(
                            AccountNonce::new(1),
                            AccountCommand::FillOrder(
                                order_id,
                                Amount::from_atoms(1),
                                Destination::AnyoneCanSpend,
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            Some(order_data.into()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
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
fn partially_fill_order_with_nft_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .orders_version(OrdersVersion::V1)
                                .build(),
                        )])
                        .unwrap(),
                    )
                    .build(),
            )
            .build();

        let genesis_input = TxInput::from_utxo(tf.genesis().get_id().into(), 0);
        let token_id = make_token_id(
            tf.chain_config(),
            tf.next_block_height(),
            &[genesis_input.clone()],
        )
        .unwrap();
        let nft_issuance = random_nft_issuance(tf.chain_config(), &mut rng);
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));

        // Issue an NFT
        let issue_nft_tx = TransactionBuilder::new()
            .add_input(genesis_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(nft_issuance.into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ask_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issue_nft_tx_id = issue_nft_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(issue_nft_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order selling NFT for coins
        let give_amount = Amount::from_atoms(1);
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let nft_outpoint = UtxoOutPoint::new(issue_nft_tx_id.into(), 0);
        let tx = TransactionBuilder::new()
            .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_eq!(
            Some(order_data.clone().into()),
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

        // Try to get nft by filling order with 1 atom less, getting 0 nfts
        {
            let underbid_amount = (ask_amount - Amount::from_atoms(1)).unwrap();
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(issue_nft_tx_id.into(), 1),
                    InputWitness::NoSignature(None),
                )
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        order_id,
                        underbid_amount,
                    )),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, Amount::from_atoms(0)),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(
                        ConnectTransactionError::ConstrainedValueAccumulatorError(
                            orders_accounting::Error::OrderUnderbid(order_id, underbid_amount)
                                .into(),
                            tx_id.into()
                        )
                    )
                )
            );
        }

        // Fill order with proper fill and receive 1 nft
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issue_nft_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                            order_id, ask_amount,
                        )),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            Some(order_data.into()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
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
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_with_zero(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order with 0 amount
        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, Amount::ZERO, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, Amount::ZERO))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(fill_input, InputWitness::NoSignature(None))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        match version {
            OrdersVersion::V0 => {
                // Check that order has not changed except nonce
                assert!(result.is_ok());
                assert_eq!(
                    Some(AccountNonce::new(0)),
                    tf.chainstate
                        .get_account_nonce_count(common::chain::AccountType::Order(order_id))
                        .unwrap()
                );
                assert_eq!(
                    Some(order_data.into()),
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
            }
            OrdersVersion::V1 => {
                assert_eq!(
                    result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            chainstate::CheckBlockError::CheckTransactionFailed(
                                CheckBlockTransactionsError::CheckTransactionError(
                                    tx_verifier::CheckTransactionError::AttemptToFillOrderWithZero(
                                        order_id, tx_id
                                    )
                                )
                            )
                        )
                    )
                );
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_underbid(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        use orders_accounting::calculate_filled_amount;

        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let min_ask_atoms = 1000;
        let max_ask_atoms = 2000;
        let min_give_atoms = 100;
        let max_give_atoms = 200;

        let token_amount_to_mint = Amount::from_atoms(rng.gen_range(max_give_atoms..100_000_000));
        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_amount_from_genesis(&mut rng, &mut tf, token_amount_to_mint);

        let ask_amount = Amount::from_atoms(rng.gen_range(min_ask_atoms..max_ask_atoms));
        let give_amount = Amount::from_atoms(rng.gen_range(min_give_atoms..=max_give_atoms));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let max_fill_atoms = ask_amount.into_atoms() / give_amount.into_atoms() - 1;
        let fill_amount = Amount::from_atoms(rng.gen_range(1..=max_fill_atoms));

        // Sanity check: the filled_amount is zero.
        // Note:
        // a) we can't use calculate_fill_order, because it'd fail with OrderUnderbid for orders V1;
        // b) we can use original ask/give amounts for orders V0, since it's our first fill.
        let filled_amount = calculate_filled_amount(ask_amount, give_amount, fill_amount).unwrap();
        assert_eq!(filled_amount, Amount::ZERO);

        // Fill the order
        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount))
            }
        };
        let tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_input, InputWitness::NoSignature(None))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        match version {
            OrdersVersion::V0 => {
                // The ask balance must have changed, but the give balance must not.
                let expected_ask_balance = (ask_amount - fill_amount).unwrap();
                assert!(result.is_ok());
                assert_eq!(
                    tf.chainstate
                        .get_account_nonce_count(common::chain::AccountType::Order(order_id))
                        .unwrap(),
                    Some(AccountNonce::new(0))
                );
                assert_eq!(
                    tf.chainstate.get_order_data(&order_id).unwrap(),
                    Some(order_data.into())
                );
                assert_eq!(
                    tf.chainstate.get_order_ask_balance(&order_id).unwrap(),
                    Some(expected_ask_balance),
                );
                assert_eq!(
                    tf.chainstate.get_order_give_balance(&order_id).unwrap(),
                    Some(give_amount),
                );
            }
            OrdersVersion::V1 => {
                assert_eq!(
                    result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::StateUpdateFailed(
                            ConnectTransactionError::ConstrainedValueAccumulatorError(
                                orders_accounting::Error::OrderUnderbid(order_id, fill_amount)
                                    .into(),
                                tx_id.into()
                            )
                        )
                    )
                );
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), vec![108, 56, 65, 38, 217, 22, 244, 28, 38, 184])]
fn fill_orders_shuffle(#[case] seed: Seed, #[case] fills: Vec<u128>) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let mut fill_order_atoms = fills.clone();
        fill_order_atoms.shuffle(&mut rng);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(1000);
        let give_amount = Amount::from_atoms(1001);
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );
        assert_eq!(ask_amount.into_atoms(), fill_order_atoms.iter().sum());

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Create a tx with utxos per fill
        let mut tx_builder = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None));
        for to_fill in &fill_order_atoms {
            tx_builder = tx_builder.add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(*to_fill)),
                Destination::AnyoneCanSpend,
            ));
        }
        let tx_with_coins_to_fill = tx_builder.build();
        let tx_with_coins_to_fill_id = tx_with_coins_to_fill.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_coins_to_fill)
            .build_and_process(&mut rng)
            .unwrap();

        let mut fill_txs = Vec::new();
        for (i, fill_atoms) in fill_order_atoms.iter().enumerate() {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_with_coins_to_fill_id.into(), i as u32),
                    InputWitness::NoSignature(None),
                )
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        order_id,
                        Amount::from_atoms(*fill_atoms),
                    )),
                    InputWitness::NoSignature(None),
                )
                // ignore outputs for simplicity
                .build();
            fill_txs.push(tx);
        }

        tf.make_block_builder()
            .with_transactions(fill_txs)
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            Some(order_data.into()),
            tf.chainstate.get_order_data(&order_id).unwrap()
        );
        assert_eq!(
            None,
            tf.chainstate.get_order_ask_balance(&order_id).unwrap()
        );
        assert_eq!(
            Some(Amount::from_atoms(1)),
            tf.chainstate.get_order_give_balance(&order_id).unwrap()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn orders_v1_activation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        // activate orders v1 at height 5 (genesis + issue token block + mint block + create order block + empty block)
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .orders_version(OrdersVersion::V0)
                                    .build(),
                            ),
                            (
                                BlockHeight::new(5),
                                ChainstateUpgradeBuilder::latest()
                                    .orders_version(OrdersVersion::V1)
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let order_data = Box::new(OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(Amount::from_atoms(rng.gen_range(1u128..1000))),
            OutputValue::TokenV1(
                token_id,
                Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms())),
            ),
        ));

        // Create an order
        let order_creation_tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(order_data))
            .build();
        let order_id = make_order_id(order_creation_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order_creation_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Try to fill order before activation, check an error
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        order_id,
                        Amount::ZERO,
                    )),
                    InputWitness::NoSignature(None),
                )
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::CheckBlockFailed(
                        chainstate::CheckBlockError::CheckTransactionFailed(
                            chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                tx_verifier::CheckTransactionError::OrdersV1AreNotActivated(tx_id)
                            )
                        )
                    )
                )
            );
        }

        // Try to conclude order before activation, check an error
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id)),
                    InputWitness::NoSignature(None),
                )
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::CheckBlockFailed(
                        chainstate::CheckBlockError::CheckTransactionFailed(
                            chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                tx_verifier::CheckTransactionError::OrdersV1AreNotActivated(tx_id)
                            )
                        )
                    )
                )
            );
        }

        // produce an empty block and activate fork
        tf.make_block_builder().build_and_process(&mut rng).unwrap();

        // Try to fill order with deprecated command, check an error
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::AccountCommand(
                        AccountNonce::new(0),
                        AccountCommand::FillOrder(
                            order_id,
                            Amount::ZERO,
                            Destination::AnyoneCanSpend,
                        ),
                    ),
                    InputWitness::NoSignature(None),
                )
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::CheckBlockFailed(
                        chainstate::CheckBlockError::CheckTransactionFailed(
                            chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                tx_verifier::CheckTransactionError::DeprecatedOrdersCommands(tx_id)
                            )
                        )
                    )
                )
            );
        }

        // Try to conclude order before activation, check an error
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::AccountCommand(
                        AccountNonce::new(0),
                        AccountCommand::ConcludeOrder(order_id),
                    ),
                    InputWitness::NoSignature(None),
                )
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::CheckBlockFailed(
                        chainstate::CheckBlockError::CheckTransactionFailed(
                            chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                tx_verifier::CheckTransactionError::DeprecatedOrdersCommands(tx_id)
                            )
                        )
                    )
                )
            );
        }

        // now it should be possible to use OrderAccountCommand
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id)),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Create an order, fill it partially.
// Activate Orders V1 fork.
// Fill partially again and conclude.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_fill_activate_fork_fill_conclude(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        // activate orders at height 5 (genesis + issue token block + mint + create order + fill)
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .orders_version(OrdersVersion::V0)
                                    .build(),
                            ),
                            (
                                BlockHeight::new(5),
                                ChainstateUpgradeBuilder::latest()
                                    .orders_version(OrdersVersion::V1)
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(1000);
        let give_amount = tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(100);
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, OrdersVersion::V0);

        let fill_tx_1 = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(
                TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(fill_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let fill_tx_1_id = fill_tx_1.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(fill_tx_1)
            .build_and_process(&mut rng)
            .unwrap();

        // Next block should activate orders V1
        assert_eq!(BlockHeight::new(4), tf.best_block_index().block_height());

        // Fill again now with V1
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, OrdersVersion::V1);

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(fill_tx_1_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                            order_id,
                            fill_amount,
                        )),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, filled_amount),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Conclude the order
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(
                    token_id,
                    (give_amount - filled_amount).and_then(|v| v - filled_amount).unwrap(),
                ),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((fill_amount * 2).unwrap()),
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
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn freeze_order_check_storage(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_creation_tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(order_creation_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order_creation_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Try freeze nonexisting order
        {
            let random_order_id = OrderId::new(H256::random_using(&mut rng));
            let freeze_tx = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(random_order_id)),
                    InputWitness::NoSignature(None),
                )
                .build();
            let freeze_tx_id = freeze_tx.transaction().get_id();
            let result =
                tf.make_block_builder().add_transaction(freeze_tx).build_and_process(&mut rng);

            match version {
                OrdersVersion::V0 => {
                    assert_eq!(
                        result.unwrap_err(),
                        chainstate::ChainstateError::ProcessBlockError(
                            chainstate::BlockError::CheckBlockFailed(
                                chainstate::CheckBlockError::CheckTransactionFailed(
                                    CheckBlockTransactionsError::CheckTransactionError(
                                        tx_verifier::CheckTransactionError::OrdersV1AreNotActivated(
                                            freeze_tx_id
                                        )
                                    )
                                )
                            )
                        )
                    );
                }
                OrdersVersion::V1 => {
                    assert_eq!(
                        result.unwrap_err(),
                        chainstate::ChainstateError::ProcessBlockError(
                            chainstate::BlockError::StateUpdateFailed(
                                ConnectTransactionError::InputCheck(InputCheckError::new(
                                    0,
                                    TranslationError::OrderNotFound(random_order_id)
                                ))
                            )
                        )
                    );
                }
            }
        }

        let freeze_tx = TransactionBuilder::new()
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
            .build();
        let freeze_tx_id = freeze_tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(freeze_tx).build_and_process(&mut rng);

        match version {
            OrdersVersion::V0 => {
                assert_eq!(
                    result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            chainstate::CheckBlockError::CheckTransactionFailed(
                                chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                    tx_verifier::CheckTransactionError::OrdersV1AreNotActivated(
                                        freeze_tx_id
                                    )
                                )
                            )
                        )
                    )
                );
            }
            OrdersVersion::V1 => {
                assert!(result.is_ok());

                let expecter_order_data =
                    orders_accounting::OrderData::from(order_data).try_freeze().unwrap();
                assert_eq!(
                    Some(expecter_order_data),
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
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn freeze_order_check_signature(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (order_sk, order_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let (token_id, tokens_outpoint, _) = issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::PublicKey(order_pk.clone()),
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
            .build();

        let input_commitments = tf.make_sighash_input_commitments_for_transaction_inputs(
            tx.inputs(),
            tf.next_block_height(),
        );

        // try freeze without signature
        {
            let result =
                tf.make_block_builder().add_transaction(tx.clone()).build_and_process(&mut rng);

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

        // try conclude with wrong signature
        {
            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            let tx = SignedTransaction::new(
                tx.transaction().clone(),
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
        {
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &order_sk,
                Default::default(),
                Destination::PublicKey(order_pk),
                &tx,
                &input_commitments,
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
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fill_freeze_conclude_order(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..=ask_amount.into_atoms()));
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, OrdersVersion::V1);
        let left_to_fill = (ask_amount - fill_amount).unwrap();
        let fill_tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount)),
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
        let fill_tx_id = fill_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(fill_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Freeze the order
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Try filling the order after freeze
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(fill_tx_id.into(), 1),
                    InputWitness::NoSignature(None),
                )
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        order_id,
                        left_to_fill,
                    )),
                    InputWitness::NoSignature(None),
                )
                // ignore outputs for simplicity
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            if left_to_fill != Amount::ZERO {
                assert_eq!(
                    result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::StateUpdateFailed(
                            ConnectTransactionError::ConstrainedValueAccumulatorError(
                                orders_accounting::Error::AttemptedFillFrozenOrder(order_id,)
                                    .into(),
                                tx_id.into()
                            )
                        )
                    )
                );
            } else {
                // Note: in orders V1 zero fills are not allowed and the zero fill check happens earlier,
                // so we'll hit this error instead.
                assert_eq!(
                    result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            CheckBlockError::CheckTransactionFailed(
                                CheckBlockTransactionsError::CheckTransactionError(
                                    CheckTransactionError::AttemptToFillOrderWithZero(
                                        order_id, tx_id
                                    )
                                )
                            )
                        )
                    )
                );
            }
        }

        //Try freezing the order once more
        {
            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(
                                order_id,
                            )),
                            InputWitness::NoSignature(None),
                        )
                        .build(),
                )
                .build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(
                        ConnectTransactionError::OrdersAccountingError(
                            orders_accounting::Error::AttemptedFreezeAlreadyFrozenOrder(order_id,)
                        )
                    )
                )
            );
        }

        // Conclude frozen order
        let conclude_tx = TransactionBuilder::new()
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
            // ignore outputs for simplicity
            .build();
        tf.make_block_builder()
            .add_transaction(conclude_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Try freezing concluded order
        {
            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(
                                order_id,
                            )),
                            InputWitness::NoSignature(None),
                        )
                        .build(),
                )
                .build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                        InputCheckError::new(0, TranslationError::OrderNotFound(order_id))
                    ))
                )
            );
        }
    });
}

// Orders with zero values are not allowed.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn order_with_zero_value(#[case] seed: Seed, #[case] version: OrdersVersion) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let tokens_circulating_supply =
            tf.chainstate.get_token_circulating_supply(&token_id).unwrap().unwrap();

        let (coins, tokens) = match rng.gen_range(0..3) {
            0 => {
                let token_amount = Amount::from_atoms(
                    rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()),
                );
                (
                    OutputValue::Coin(Amount::ZERO),
                    OutputValue::TokenV1(token_id, token_amount),
                )
            }
            1 => {
                let coin_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
                (
                    OutputValue::Coin(coin_amount),
                    OutputValue::TokenV1(token_id, Amount::ZERO),
                )
            }
            _ => (
                OutputValue::Coin(Amount::ZERO),
                OutputValue::TokenV1(token_id, Amount::ZERO),
            ),
        };

        let (ask, give) = if rng.gen_bool(0.5) {
            (coins, tokens)
        } else {
            (tokens, coins)
        };

        log::debug!("ask = {ask:?}, give = {give:?}");

        let order_data = OrderData::new(Destination::AnyoneCanSpend, ask, give);

        let tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::StateUpdateFailed(
                    ConnectTransactionError::OrdersAccountingError(
                        orders_accounting::Error::OrderWithZeroValue(order_id)
                    )
                )
            )
        );
    });
}

// The destination specified in v0 FillOrder inputs exists only due to historical reasons.
// So this test proves that:
// 1) The destination doesn't have to be the same as the actual output destination.
// 2) The signature for a FillOrder input is not enforced, i.e. it can be empty or correspond
// to some unrelated destination or contain arbitrary data.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fill_order_v0_destination_irrelevancy(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, OrdersVersion::V0);

        let (token_id, tokens_outpoint, mut coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);

        let initial_ask_amount = Amount::from_atoms(rng.gen_range(1000..2000));
        let initial_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(initial_ask_amount),
            OutputValue::TokenV1(token_id, initial_give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let (_, pk1) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (sk2, pk2) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (_, pk3) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let output_destination = if rng.gen_bool(0.5) {
            Destination::PublicKey(pk3)
        } else {
            Destination::AnyoneCanSpend
        };

        let mut total_fill_amount = Amount::ZERO;
        let mut total_filled_amount = Amount::ZERO;

        // The destination in FillOrder is PublicKey(pk1), the input is not signed.
        // The actual output destination is output_destination.
        {
            let fill_amount1 =
                Amount::from_atoms(rng.gen_range(1..initial_ask_amount.into_atoms() / 10));
            let filled_amount1 =
                calculate_fill_order(&tf, &order_id, fill_amount1, OrdersVersion::V0);
            let fill_order_input1 = TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(
                    order_id,
                    fill_amount1,
                    Destination::PublicKey(pk1.clone()),
                ),
            );

            let coins_left = tf.coin_amount_from_utxo(&coins_outpoint);
            let change = (coins_left - fill_amount1).unwrap();
            let fill_tx_1 = TransactionBuilder::new()
                .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
                .add_input(fill_order_input1, InputWitness::NoSignature(None))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, filled_amount1),
                    output_destination.clone(),
                ))
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(change),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let fill_tx_1_id = fill_tx_1.transaction().get_id();
            coins_outpoint = UtxoOutPoint::new(fill_tx_1_id.into(), 1);

            tf.make_block_builder()
                .add_transaction(fill_tx_1)
                .build_and_process(&mut rng)
                .unwrap();

            total_fill_amount = (total_fill_amount + fill_amount1).unwrap();
            total_filled_amount = (total_filled_amount + filled_amount1).unwrap();
        }

        // The destination in FillOrder is PublicKey(pk1), the input is signed by pk2.
        // The actual output destination is output_destination.
        {
            let fill_amount2 =
                Amount::from_atoms(rng.gen_range(1..initial_ask_amount.into_atoms() / 10));
            let filled_amount2 =
                calculate_fill_order(&tf, &order_id, fill_amount2, OrdersVersion::V0);
            let fill_order_input2 = TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::FillOrder(
                    order_id,
                    fill_amount2,
                    Destination::PublicKey(pk1.clone()),
                ),
            );

            let coins_left = tf.coin_amount_from_utxo(&coins_outpoint);
            let change = (coins_left - fill_amount2).unwrap();
            let coins_utxo = tf.utxo(&coins_outpoint).take_output();
            let fill_tx_2 = Transaction::new(
                0,
                vec![coins_outpoint.clone().into(), fill_order_input2],
                vec![
                    TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, filled_amount2),
                        output_destination.clone(),
                    ),
                    TxOutput::Transfer(OutputValue::Coin(change), Destination::AnyoneCanSpend),
                ],
            )
            .unwrap();
            let fill_tx_2_id = fill_tx_2.get_id();
            let fill_input_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &sk2,
                Default::default(),
                Destination::PublicKey(pk2),
                &fill_tx_2,
                &[
                    SighashInputCommitment::Utxo(Cow::Borrowed(&coins_utxo)),
                    SighashInputCommitment::None,
                ],
                0,
                &mut rng,
            )
            .unwrap();
            let fill_tx_2 = SignedTransaction::new(
                fill_tx_2,
                vec![InputWitness::NoSignature(None), InputWitness::Standard(fill_input_sig)],
            )
            .unwrap();

            tf.make_block_builder()
                .add_transaction(fill_tx_2)
                .build_and_process(&mut rng)
                .unwrap();

            total_fill_amount = (total_fill_amount + fill_amount2).unwrap();
            total_filled_amount = (total_filled_amount + filled_amount2).unwrap();
            coins_outpoint = UtxoOutPoint::new(fill_tx_2_id.into(), 1);
        }

        // The destination in FillOrder is PublicKey(pk1), the signature is bogus.
        // The actual output destination is output_destination.
        {
            let fill_amount3 =
                Amount::from_atoms(rng.gen_range(1..initial_ask_amount.into_atoms() / 10));
            let filled_amount3 =
                calculate_fill_order(&tf, &order_id, fill_amount3, OrdersVersion::V0);
            let fill_order_input3 = TxInput::AccountCommand(
                AccountNonce::new(2),
                AccountCommand::FillOrder(
                    order_id,
                    fill_amount3,
                    Destination::PublicKey(pk1.clone()),
                ),
            );

            let coins_left = tf.coin_amount_from_utxo(&coins_outpoint);
            let change = (coins_left - fill_amount3).unwrap();
            let fill_tx_3 = Transaction::new(
                0,
                vec![coins_outpoint.into(), fill_order_input3],
                vec![
                    TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, filled_amount3),
                        output_destination,
                    ),
                    TxOutput::Transfer(OutputValue::Coin(change), Destination::AnyoneCanSpend),
                ],
            )
            .unwrap();
            let fill_input_sig = StandardInputSignature::new(
                SigHashType::all(),
                gen_random_bytes(&mut rng, 100, 200),
            );
            let fill_tx_3 = SignedTransaction::new(
                fill_tx_3,
                vec![InputWitness::NoSignature(None), InputWitness::Standard(fill_input_sig)],
            )
            .unwrap();

            tf.make_block_builder()
                .add_transaction(fill_tx_3)
                .build_and_process(&mut rng)
                .unwrap();

            total_fill_amount = (total_fill_amount + fill_amount3).unwrap();
            total_filled_amount = (total_filled_amount + filled_amount3).unwrap();
        }

        let expected_ask_balance = (initial_ask_amount - total_fill_amount).unwrap();
        let expected_give_balance = (initial_give_amount - total_filled_amount).unwrap();

        assert_eq!(
            tf.chainstate.get_order_data(&order_id).unwrap(),
            Some(order_data.into()),
        );
        assert_eq!(
            tf.chainstate.get_order_ask_balance(&order_id).unwrap(),
            Some(expected_ask_balance),
        );
        assert_eq!(
            tf.chainstate.get_order_give_balance(&order_id).unwrap(),
            Some(expected_give_balance),
        );
    });
}

// In orders v1, the signature for a FillOrder input must be empty.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fill_order_v1_must_not_be_signed(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, OrdersVersion::V1);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let coins_utxo = tf.utxo(&coins_outpoint).take_output();

        let initial_ask_amount = Amount::from_atoms(rng.gen_range(1000..2000));
        let initial_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(initial_ask_amount),
            OutputValue::TokenV1(token_id, initial_give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let (sk, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let output_destination = Destination::PublicKey(pk);

        let min_fill_amount =
            initial_ask_amount.into_atoms().div_ceil(initial_give_amount.into_atoms());
        let fill_amount = Amount::from_atoms(
            rng.gen_range(min_fill_amount..initial_ask_amount.into_atoms() / 10),
        );
        let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, OrdersVersion::V1);
        let fill_order_input =
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount));
        let coins_left = tf.coin_amount_from_utxo(&coins_outpoint);
        let change = (coins_left - fill_amount).unwrap();

        let fill_tx = Transaction::new(
            0,
            vec![coins_outpoint.clone().into(), fill_order_input],
            vec![
                TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, filled_amount),
                    output_destination.clone(),
                ),
                TxOutput::Transfer(OutputValue::Coin(change), Destination::AnyoneCanSpend),
            ],
        )
        .unwrap();

        // The input is signed; this should be rejected with DestinationSigError::SignatureNotNeeded.
        {
            let input_commitments = [
                SighashInputCommitment::Utxo(Cow::Borrowed(&coins_utxo)),
                SighashInputCommitment::None,
            ];
            let fill_input_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &sk,
                Default::default(),
                output_destination.clone(),
                &fill_tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();
            let fill_tx = SignedTransaction::new(
                fill_tx.clone(),
                vec![
                    InputWitness::NoSignature(None),
                    InputWitness::Standard(fill_input_sig.clone()),
                ],
            )
            .unwrap();

            let expected_input_check_err = InputCheckError::new(
                1,
                InputCheckErrorPayload::Verification(ScriptError::Signature(
                    DestinationSigError::SignatureNotNeeded,
                )),
            );
            // First of all, verify the input via `verify_tx_signature`, this should fail with
            // SignatureNotNeeded too.
            let err = verify_tx_signature(
                tf.chain_config(),
                // Note: this destination will be ignored; mintscript should choose AnyoneCanSpend
                // as the appropriate destination for FillOrder in orders v1.
                &output_destination,
                &fill_tx,
                &input_commitments,
                1,
                None,
            )
            .unwrap_err();
            assert_eq!(err, expected_input_check_err);

            // As a sanity check, verify the actual signature via the lower-level `verify_signature` call.
            let result = verify_signature(
                tf.chain_config(),
                &output_destination,
                &fill_tx,
                &EvaluatedInputWitness::Standard(fill_input_sig.clone()),
                &input_commitments,
                1,
            );
            assert_eq!(result, Ok(()));

            // Now try mining the tx, expecting SignatureNotNeeded.
            let err = tf
                .make_block_builder()
                .add_transaction(fill_tx)
                .build_and_process(&mut rng)
                .unwrap_err();

            let expected_err = ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(expected_input_check_err),
            ));
            assert_eq!(err, expected_err);
        }

        // The input is not signed.
        {
            let fill_tx = SignedTransaction::new(
                fill_tx,
                vec![InputWitness::NoSignature(None), InputWitness::NoSignature(None)],
            )
            .unwrap();

            tf.make_block_builder()
                .add_transaction(fill_tx)
                .build_and_process(&mut rng)
                .unwrap();
        }

        let expected_ask_balance = (initial_ask_amount - fill_amount).unwrap();
        let expected_give_balance = (initial_give_amount - filled_amount).unwrap();

        assert_eq!(
            tf.chainstate.get_order_data(&order_id).unwrap(),
            Some(order_data.into()),
        );
        assert_eq!(
            tf.chainstate.get_order_ask_balance(&order_id).unwrap(),
            Some(expected_ask_balance),
        );
        assert_eq!(
            tf.chainstate.get_order_give_balance(&order_id).unwrap(),
            Some(expected_give_balance),
        );
    });
}

// Fill the same order twice using two different transactions in the same block.
// Note that we have 2 cases for each OrdersVersion - one where the fill amounts are different and
// another one where they are the same. The latter case is important in the v1 scenario, where
// it creates a block with 2 identical inputs among its transactions (which would normally be
// rejected with the DuplicateInputInBlock error, but v1 FillOrder inputs are an exception).
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_twice_in_same_block(
    #[case] seed: Seed,
    #[case] version: OrdersVersion,
    #[values(false, true)] use_same_amount: bool,
) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_from_genesis(&mut rng, &mut tf);
        let coins_amount = tf.coin_amount_from_utxo(&coins_outpoint);

        let initial_ask_amount = Amount::from_atoms(rng.gen_range(1000..2000));
        let initial_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(initial_ask_amount),
            OutputValue::TokenV1(token_id, initial_give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let output_destination = Destination::PublicKey(pk);

        let fill_amount1 =
            Amount::from_atoms(rng.gen_range(1..initial_ask_amount.into_atoms() / 3));
        let fill_amount2 = if use_same_amount {
            fill_amount1
        } else {
            (|| {
                for _ in 0..1000 {
                    let new_amount =
                        Amount::from_atoms(rng.gen_range(1..initial_ask_amount.into_atoms() / 3));
                    if new_amount != fill_amount1 {
                        return new_amount;
                    }
                }
                panic!("Can't generate a distinct amount");
            })()
        };

        let filled_amount1 = calculate_fill_order(&tf, &order_id, fill_amount1, version);
        let filled_amount2 = {
            // Note: we can't use `calculate_fill_order` to calculate the second filled amount in orders v0,
            // because it depends on the balances after the first fill, which hasn't been mined yet.
            // So we have to use the low-level `calculate_filled_amount`.
            let expected_ask_balance_after_first_fill =
                (initial_ask_amount - fill_amount1).unwrap();
            let expected_give_balance_after_first_fill =
                (initial_give_amount - filled_amount1).unwrap();

            match version {
                OrdersVersion::V0 => orders_accounting::calculate_filled_amount(
                    expected_ask_balance_after_first_fill,
                    expected_give_balance_after_first_fill,
                    fill_amount2,
                )
                .unwrap(),
                OrdersVersion::V1 => orders_accounting::calculate_filled_amount(
                    initial_ask_amount,
                    initial_give_amount,
                    fill_amount2,
                )
                .unwrap(),
            }
        };

        let fill_order_input1 = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount1, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount1))
            }
        };
        let fill_order_input2 = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::FillOrder(order_id, fill_amount2, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount2))
            }
        };

        let coins_after_first_fill = (coins_amount - fill_amount1).unwrap();
        let fill_tx_1 = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_order_input1, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount1),
                output_destination.clone(),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(coins_after_first_fill),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let fill_tx_1_id = fill_tx_1.transaction().get_id();

        let coins_outpoint = UtxoOutPoint::new(fill_tx_1_id.into(), 1);

        let coins_after_second_fill = (coins_after_first_fill - fill_amount2).unwrap();
        let fill_tx_2 = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(fill_order_input2, InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount2),
                output_destination.clone(),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(coins_after_second_fill),
                Destination::AnyoneCanSpend,
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(fill_tx_1)
            .add_transaction(fill_tx_2)
            .build_and_process(&mut rng)
            .unwrap();

        let total_fill_amount = (fill_amount1 + fill_amount2).unwrap();
        let total_filled_amount = (filled_amount1 + filled_amount2).unwrap();
        let expected_ask_balance = (initial_ask_amount - total_fill_amount).unwrap();
        let expected_give_balance = (initial_give_amount - total_filled_amount).unwrap();

        assert_eq!(
            tf.chainstate.get_order_data(&order_id).unwrap(),
            Some(order_data.into()),
        );
        assert_eq!(
            tf.chainstate.get_order_ask_balance(&order_id).unwrap(),
            Some(expected_ask_balance),
        );
        assert_eq!(
            tf.chainstate.get_order_give_balance(&order_id).unwrap(),
            Some(expected_give_balance),
        );
    });
}

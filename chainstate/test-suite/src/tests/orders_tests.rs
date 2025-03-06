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

use chainstate::{CheckBlockTransactionsError, ConnectTransactionError};
use chainstate_storage::Transactional;
use chainstate_test_framework::{output_value_amount, TestFramework, TransactionBuilder};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        make_order_id,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            DestinationSigError,
        },
        tokens::{
            make_token_id, IsTokenFreezable, TokenId, TokenIssuance, TokenIssuanceV1,
            TokenTotalSupply,
        },
        AccountCommand, AccountNonce, Destination, OrderAccountCommand, OrderData, OrdersVersion,
        SignedTransaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Idable},
};
use crypto::key::{KeyKind, PrivateKey};
use orders_accounting::OrdersAccountingDB;
use randomness::{CryptoRng, Rng, SliceRandom};
use rstest::rstest;
use test_utils::{
    nft_utils::random_nft_issuance,
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};
use tx_verifier::error::{InputCheckError, ScriptError, TranslationError};

use crate::tests::helpers::{
    chainstate_upgrade_builder::ChainstateUpgradeBuilder, issue_token_from_block,
    mint_tokens_in_block,
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
    let genesis_block_id = tf.genesis().get_id();
    let utxo = UtxoOutPoint::new(genesis_block_id.into(), 0);

    issue_and_mint_token_from_best_block(rng, tf, utxo)
}

fn issue_and_mint_token_from_best_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    utxo_outpoint: UtxoOutPoint,
) -> (TokenId, UtxoOutPoint, UtxoOutPoint) {
    let best_block_id = tf.best_block_id();
    let issuance = {
        let max_ticker_len = tf.chain_config().token_max_ticker_len();
        let max_dec_count = tf.chain_config().token_max_dec_count();
        let max_uri_len = tf.chain_config().token_max_uri_len();

        let issuance = TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(rng, 1..max_ticker_len)
                .as_bytes()
                .to_vec(),
            number_of_decimals: rng.gen_range(1..max_dec_count),
            metadata_uri: random_ascii_alphanumeric_string(rng, 1..max_uri_len).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            is_freezable: IsTokenFreezable::Yes,
            authority: Destination::AnyoneCanSpend,
        };
        TokenIssuance::V1(issuance)
    };

    let (token_id, _, utxo_with_change) =
        issue_token_from_block(rng, tf, best_block_id, utxo_outpoint, issuance);

    let to_mint = Amount::from_atoms(rng.gen_range(100..100_000_000));

    let best_block_id = tf.best_block_id();
    let (_, mint_tx_id) = mint_tokens_in_block(
        rng,
        tf,
        best_block_id,
        utxo_with_change,
        token_id,
        to_mint,
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
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
fn create_two_same_orders_in_tx(#[case] seed: Seed) {
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
fn create_two_orders_same_tx(#[case] seed: Seed) {
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
fn create_two_orders_same_block(#[case] seed: Seed) {
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

        let (token_id_2, tokens_outpoint_2, _) =
            issue_and_mint_token_from_best_block(&mut rng, &mut tf, coins_outpoint);

        let tokens_circulating_supply_2 =
            tf.chainstate.get_token_circulating_supply(&token_id_2).unwrap().unwrap();

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..tokens_circulating_supply_2.into_atoms()));

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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
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
        let tx = TransactionBuilder::new()
            .add_input(tx_input, InputWitness::NoSignature(None))
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..ask_amount.into_atoms()));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, fill_amount, version)
                .unwrap()
        };
        let left_to_fill = (ask_amount - fill_amount).unwrap();

        let fill_order_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                fill_amount,
                Destination::AnyoneCanSpend,
            )),
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
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, left_to_fill, version)
                .unwrap()
        };

        let fill_order_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(1),
                AccountCommand::FillOrder(order_id, left_to_fill, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                left_to_fill,
                Destination::AnyoneCanSpend,
            )),
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..=ask_amount.into_atoms()));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, fill_amount, version)
                .unwrap()
        };

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                fill_amount,
                Destination::AnyoneCanSpend,
            )),
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
                    Destination::AnyoneCanSpend,
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

        let order_id = make_order_id(&tokens_outpoint);
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
        let tx_id = tx.transaction().get_id();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, ask_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                ask_amount,
                Destination::AnyoneCanSpend,
            )),
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
                Destination::AnyoneCanSpend,
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        {
            // Try overspend complete fill order
            let fill_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(0),
                    AccountCommand::FillOrder(order_id, ask_amount, Destination::AnyoneCanSpend),
                ),
                OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id,
                    ask_amount,
                    Destination::AnyoneCanSpend,
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
                    Destination::AnyoneCanSpend,
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
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                ask_amount,
                Destination::AnyoneCanSpend,
            )),
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

        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount =
            Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms()));
        let order_data = OrderData::new(
            Destination::PublicKey(order_pk.clone()),
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // try conclude without signature
        {
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

        // try conclude with wrong signature
        {
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..ask_amount.into_atoms()));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, fill_amount, version)
                .unwrap()
        };
        let left_to_fill = (ask_amount - fill_amount).unwrap();

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                fill_amount,
                Destination::AnyoneCanSpend,
            )),
        };
        let tx = TransactionBuilder::new()
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
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            // transfer output just to be able to spend something in alternative branch
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
        let reorg_common_ancestor = tf.best_block_id();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..ask_amount.into_atoms()));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(&orders_db, order_id, fill_amount, version)
                .unwrap()
        };
        let left_to_fill = (ask_amount - fill_amount).unwrap();

        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                fill_amount,
                Destination::AnyoneCanSpend,
            )),
        };
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
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
                    .build(),
            )
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
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(conclude_input, InputWitness::NoSignature(None))
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
        let token_id = make_token_id(&[genesis_input.clone()]).unwrap();
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
        let order_id = make_order_id(&nft_outpoint);
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

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
                    order_id,
                    ask_amount,
                    Destination::AnyoneCanSpend,
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
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                ask_amount,
                Destination::AnyoneCanSpend,
            )),
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
        let token_id = make_token_id(&[genesis_input.clone()]).unwrap();
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
        let order_id = make_order_id(&nft_outpoint);
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

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
        let token_id = make_token_id(&[genesis_input.clone()]).unwrap();
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
        let order_id = make_order_id(&nft_outpoint);
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

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
                        Destination::AnyoneCanSpend,
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
                            order_id,
                            ask_amount,
                            Destination::AnyoneCanSpend,
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order with 0 amount
        let fill_input = match version {
            OrdersVersion::V0 => TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(order_id, Amount::ZERO, Destination::AnyoneCanSpend),
            ),
            OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                Amount::ZERO,
                Destination::AnyoneCanSpend,
            )),
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
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
            // Destination of fill order must be unique to avoid duplicating inputs
            let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_with_coins_to_fill_id.into(), i as u32),
                    InputWitness::NoSignature(None),
                )
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        order_id,
                        Amount::from_atoms(*fill_atoms),
                        Destination::PublicKey(pk),
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

        let order_id = make_order_id(&tokens_outpoint);
        let order_data = Box::new(OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(Amount::from_atoms(rng.gen_range(1u128..1000))),
            OutputValue::TokenV1(
                token_id,
                Amount::from_atoms(rng.gen_range(1u128..=tokens_circulating_supply.into_atoms())),
            ),
        ));

        // Create an order
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::CreateOrder(order_data))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Try to fill order before activation, check an error
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        order_id,
                        Amount::ZERO,
                        Destination::AnyoneCanSpend,
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill the order partially
        let fill_amount = Amount::from_atoms(100);
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(
                &orders_db,
                order_id,
                fill_amount,
                OrdersVersion::V0,
            )
            .unwrap()
        };

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
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(
                &orders_db,
                order_id,
                fill_amount,
                OrdersVersion::V1,
            )
            .unwrap()
        };

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
                            Destination::AnyoneCanSpend,
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        match version {
            OrdersVersion::V0 => {
                assert_eq!(
                    result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            chainstate::CheckBlockError::CheckTransactionFailed(
                                chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                    tx_verifier::CheckTransactionError::OrdersV1AreNotActivated(
                                        tx_id
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // try freeze without signature
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
                    InputWitness::NoSignature(None),
                )
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

        // try conclude with wrong signature
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
                    InputWitness::NoSignature(None),
                )
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
                TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
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

        let order_id = make_order_id(&tokens_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Fill order partially
        let fill_amount = Amount::from_atoms(rng.gen_range(1..ask_amount.into_atoms()));
        let filled_amount = {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(
                &orders_db,
                order_id,
                fill_amount,
                OrdersVersion::V1,
            )
            .unwrap()
        };
        let left_to_fill = (ask_amount - fill_amount).unwrap();
        let fill_tx = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id,
                    fill_amount,
                    Destination::AnyoneCanSpend,
                )),
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
                        Destination::AnyoneCanSpend,
                    )),
                    InputWitness::NoSignature(None),
                )
                // ignore outputs for simplicity
                .build();
            let tx_id = tx.transaction().get_id();
            let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(
                        ConnectTransactionError::ConstrainedValueAccumulatorError(
                            orders_accounting::Error::AttemptedFillFreezedOrder(order_id,).into(),
                            tx_id.into()
                        )
                    )
                )
            );
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
                            orders_accounting::Error::AttemptedFreezeAlreadyFreezedOrder(order_id,)
                                .into()
                        )
                    )
                )
            );
        }

        // Conclude freezed order
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

        //Try freezing concluded order
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

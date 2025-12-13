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

use std::{borrow::Cow, collections::BTreeMap};

use chainstate_storage::Transactional as _;
use orders_accounting::OrdersAccountingStorageRead as _;
use rstest::rstest;

use chainstate::{
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError,
};
use chainstate_test_framework::{
    helpers::{
        calculate_fill_order, issue_and_mint_random_token_from_best_block,
        issue_random_nft_from_best_block, order_min_non_zero_fill_amount,
    },
    output_value_amount, TestFramework, TransactionBuilder,
};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        make_order_id,
        output_value::{OutputValue, RpcOutputValue},
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::{input_commitments::SighashInputCommitment, sighashtype::SigHashType},
            verify_signature, DestinationSigError, EvaluatedInputWitness,
        },
        tokens::{IsTokenFreezable, TokenId, TokenTotalSupply},
        AccountCommand, AccountNonce, AccountType, ChainstateUpgradeBuilder, Currency, Destination,
        IdCreationError, OrderAccountCommand, OrderData, OrderId, OrdersVersion, RpcOrderInfo,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Idable, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use logging::log;
use randomness::{CryptoRng, Rng, SliceRandom};
use test_utils::random::{gen_random_bytes, make_seedable_rng, Seed};
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
) -> (
    TokenId,
    /*tokens*/ UtxoOutPoint,
    /*coins change*/ UtxoOutPoint,
) {
    let to_mint = Amount::from_atoms(rng.gen_range(100..100_000_000));
    issue_and_mint_token_amount_from_genesis(rng, tf, to_mint)
}

fn issue_and_mint_token_amount_from_genesis(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    to_mint: Amount,
) -> (
    TokenId,
    /*tokens*/ UtxoOutPoint,
    /*coins change*/ UtxoOutPoint,
) {
    let genesis_block_id = tf.genesis().get_id();
    let utxo_to_pay_fee = UtxoOutPoint::new(genesis_block_id.into(), 0);

    issue_and_mint_random_token_from_best_block(
        rng,
        tf,
        utxo_to_pay_fee,
        to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    )
}

fn issue_and_mint_token_amount_from_best_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    utxo_to_pay_fee: UtxoOutPoint,
    to_mint: Amount,
) -> (
    TokenId,
    /*tokens*/ UtxoOutPoint,
    /*coins change*/ UtxoOutPoint,
) {
    issue_and_mint_random_token_from_best_block(
        rng,
        tf,
        utxo_to_pay_fee,
        to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    )
}

struct ExpectedOrderData {
    initial_data: common::chain::OrderData,
    ask_balance: Option<Amount>,
    give_balance: Option<Amount>,
    nonce: Option<AccountNonce>,
    is_frozen: bool,
}

fn assert_order_exists(
    tf: &TestFramework,
    rng: &mut (impl Rng + CryptoRng),
    order_id: &OrderId,
    expected_data: &ExpectedOrderData,
    no_other_orders_present: bool,
) {
    let random_order_id = OrderId::random_using(rng);

    let expected_order_data = orders_accounting::OrderData::new_generic(
        expected_data.initial_data.conclude_key().clone(),
        expected_data.initial_data.ask().clone(),
        expected_data.initial_data.give().clone(),
        expected_data.is_frozen,
    );

    let actual_order_data = tf.chainstate.get_order_data(order_id).unwrap().unwrap();
    assert_eq!(actual_order_data, expected_order_data);
    assert_eq!(
        tf.chainstate.get_order_data(&random_order_id).unwrap(),
        None
    );

    let actual_ask_balance = tf.chainstate.get_order_ask_balance(order_id).unwrap();
    assert_eq!(actual_ask_balance, expected_data.ask_balance);
    assert_eq!(
        tf.chainstate.get_order_ask_balance(&random_order_id).unwrap(),
        None
    );

    let actual_give_balance = tf.chainstate.get_order_give_balance(order_id).unwrap();
    assert_eq!(actual_give_balance, expected_data.give_balance);
    assert_eq!(
        tf.chainstate.get_order_give_balance(&random_order_id).unwrap(),
        None
    );

    let expected_info_for_rpc = RpcOrderInfo {
        conclude_key: expected_data.initial_data.conclude_key().clone(),
        initially_asked: RpcOutputValue::from_output_value(expected_data.initial_data.ask())
            .unwrap(),
        initially_given: RpcOutputValue::from_output_value(expected_data.initial_data.give())
            .unwrap(),
        ask_balance: expected_data.ask_balance.unwrap_or(Amount::ZERO),
        give_balance: expected_data.give_balance.unwrap_or(Amount::ZERO),
        nonce: expected_data.nonce.clone(),
        is_frozen: expected_data.is_frozen,
    };

    let actual_info_for_rpc = tf.chainstate.get_order_info_for_rpc(order_id).unwrap().unwrap();
    assert_eq!(actual_info_for_rpc, expected_info_for_rpc);
    assert_eq!(
        tf.chainstate.get_order_info_for_rpc(&random_order_id).unwrap(),
        None
    );

    let all_order_ids = tf.chainstate.get_all_order_ids().unwrap();
    assert!(all_order_ids.contains(order_id));

    let all_infos_for_rpc =
        tf.chainstate.get_orders_info_for_rpc_by_currencies(None, None).unwrap();
    assert_eq!(
        all_infos_for_rpc.get(order_id).unwrap(),
        &expected_info_for_rpc
    );

    if no_other_orders_present {
        assert_eq!(all_order_ids.len(), 1);
        assert_eq!(all_infos_for_rpc.len(), 1);
    }

    let ask_currency = Currency::from_output_value(expected_data.initial_data.ask()).unwrap();
    let give_currency = Currency::from_output_value(expected_data.initial_data.give()).unwrap();

    // Check get_orders_info_for_rpc_by_currencies when all currency filters match or are None -
    // the order should be present in the result
    for (ask_currency_filter, give_currency_filter) in [
        (None, None),
        (Some(&ask_currency), None),
        (None, Some(&give_currency)),
        (Some(&ask_currency), Some(&give_currency)),
    ] {
        let orders_rpc_infos = tf
            .chainstate
            .get_orders_info_for_rpc_by_currencies(ask_currency_filter, give_currency_filter)
            .unwrap();
        assert_eq!(
            orders_rpc_infos.get(order_id).unwrap(),
            &expected_info_for_rpc
        );

        if no_other_orders_present {
            assert_eq!(orders_rpc_infos.len(), 1);
        }
    }

    let mut make_different_currency = |currency, other_currency| {
        if currency != other_currency && rng.gen_bool(0.5) {
            return other_currency;
        }

        match currency {
            Currency::Coin => Currency::Token(TokenId::random_using(rng)),
            Currency::Token(_) => {
                if rng.gen_bool(0.5) {
                    Currency::Coin
                } else {
                    Currency::Token(TokenId::random_using(rng))
                }
            }
        }
    };

    let different_ask_currency = make_different_currency(ask_currency, give_currency);
    let different_give_currency = make_different_currency(give_currency, ask_currency);

    // Check get_orders_info_for_rpc_by_currencies when at least one currency filter doesn't match -
    // the order should not be present in the result.
    for (ask_currency_filter, give_currency_filter) in [
        (Some(&different_ask_currency), None),
        (Some(&different_ask_currency), Some(&give_currency)),
        (None, Some(&different_give_currency)),
        (Some(&ask_currency), Some(&different_give_currency)),
        (
            Some(&different_ask_currency),
            Some(&different_give_currency),
        ),
    ] {
        let orders_rpc_infos = tf
            .chainstate
            .get_orders_info_for_rpc_by_currencies(ask_currency_filter, give_currency_filter)
            .unwrap();
        assert_eq!(orders_rpc_infos.get(order_id), None);
    }

    let actual_nonce =
        tf.chainstate.get_account_nonce_count(AccountType::Order(*order_id)).unwrap();
    assert_eq!(actual_nonce, expected_data.nonce);
    assert_eq!(
        tf.chainstate
            .get_account_nonce_count(AccountType::Order(random_order_id))
            .unwrap(),
        None
    );

    // Check the storage directly
    {
        let storage_tx = tf.storage.transaction_ro().unwrap();

        let actual_order_data = storage_tx.get_order_data(order_id).unwrap().unwrap();
        assert_eq!(actual_order_data, expected_order_data);
        assert_eq!(storage_tx.get_order_data(&random_order_id).unwrap(), None);

        let actual_ask_balance = storage_tx.get_ask_balance(order_id).unwrap();
        assert_eq!(actual_ask_balance, expected_data.ask_balance);
        assert_eq!(storage_tx.get_ask_balance(&random_order_id).unwrap(), None);

        let actual_give_balance = storage_tx.get_give_balance(order_id).unwrap();
        assert_eq!(actual_give_balance, expected_data.give_balance);
        assert_eq!(storage_tx.get_give_balance(&random_order_id).unwrap(), None);

        let all_order_ids = storage_tx.get_all_order_ids().unwrap();
        assert!(all_order_ids.contains(order_id));

        let orders_accounting_data = storage_tx.read_orders_accounting_data().unwrap();
        assert_eq!(
            orders_accounting_data.order_data.get(order_id).unwrap(),
            &expected_order_data
        );
        assert_eq!(
            orders_accounting_data.ask_balances.get(order_id),
            expected_data.ask_balance.as_ref()
        );
        assert_eq!(
            orders_accounting_data.give_balances.get(order_id),
            expected_data.give_balance.as_ref()
        );

        if no_other_orders_present {
            assert_eq!(all_order_ids.len(), 1);
            assert_eq!(orders_accounting_data.order_data.len(), 1);
            assert_eq!(
                orders_accounting_data.ask_balances.len(),
                if expected_data.ask_balance.is_some() {
                    1
                } else {
                    0
                }
            );
            assert_eq!(
                orders_accounting_data.give_balances.len(),
                if expected_data.give_balance.is_some() {
                    1
                } else {
                    0
                }
            );
        }
    }
}

trait OrdersVersionExt {
    fn v0_then_some<T>(&self, val: T) -> Option<T>;
}

impl OrdersVersionExt for OrdersVersion {
    fn v0_then_some<T>(&self, val: T) -> Option<T> {
        match self {
            OrdersVersion::V0 => Some(val),
            OrdersVersion::V1 => None,
        }
    }
}

fn assert_order_missing(tf: &TestFramework, order_id: &OrderId, no_other_orders_present: bool) {
    assert_eq!(tf.chainstate.get_order_data(order_id).unwrap(), None);

    assert_eq!(tf.chainstate.get_order_ask_balance(order_id).unwrap(), None);

    assert_eq!(
        tf.chainstate.get_order_give_balance(order_id).unwrap(),
        None
    );

    assert_eq!(
        tf.chainstate.get_order_info_for_rpc(order_id).unwrap(),
        None
    );

    let all_infos_for_rpc =
        tf.chainstate.get_orders_info_for_rpc_by_currencies(None, None).unwrap();
    assert_eq!(all_infos_for_rpc.get(order_id), None);

    let all_order_ids = tf.chainstate.get_all_order_ids().unwrap();
    assert!(!all_order_ids.contains(order_id));

    if no_other_orders_present {
        assert_eq!(all_infos_for_rpc.len(), 0);
        assert_eq!(all_order_ids.len(), 0);
    }

    // Check the storage directly
    {
        let storage_tx = tf.storage.transaction_ro().unwrap();

        assert_eq!(storage_tx.get_order_data(&order_id).unwrap(), None);
        assert_eq!(storage_tx.get_ask_balance(&order_id).unwrap(), None);
        assert_eq!(storage_tx.get_give_balance(&order_id).unwrap(), None);

        let all_order_ids = storage_tx.get_all_order_ids().unwrap();
        assert!(!all_order_ids.contains(order_id));

        let orders_accounting_data = storage_tx.read_orders_accounting_data().unwrap();
        assert_eq!(orders_accounting_data.order_data.get(order_id), None);
        assert_eq!(orders_accounting_data.ask_balances.get(order_id), None);
        assert_eq!(orders_accounting_data.give_balances.get(order_id), None);

        if no_other_orders_present {
            assert_eq!(all_order_ids.len(), 0);
            assert_eq!(orders_accounting_data.order_data.len(), 0);
            assert_eq!(orders_accounting_data.ask_balances.len(), 0);
            assert_eq!(orders_accounting_data.give_balances.len(), 0);
        }
    }
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: Some(ask_amount),
                give_balance: Some(give_amount),
                nonce: None,
                is_frozen: false,
            },
            true,
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

        assert_order_missing(&tf, &order_id, true);
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

        // Fill the order partially or completely
        let min_non_zero_fill_amount = order_min_non_zero_fill_amount(&tf, &order_id, version);
        let fill_amount = Amount::from_atoms(
            rng.gen_range(min_non_zero_fill_amount.into_atoms()..=ask_amount.into_atoms()),
        );
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data.clone(),
                ask_balance: left_to_fill.as_non_zero(),
                give_balance: (give_amount - filled_amount).unwrap().as_non_zero(),
                nonce: version.v0_then_some(AccountNonce::new(0)),
                is_frozen: false,
            },
            true,
        );

        // Note: even though zero fills are allowed in orders V0 in general, we can't do a zero
        // fill when the remaining ask balance is zero. So we skip the 2nd fill for orders V0
        // as well when the remaining balance is less than min_non_zero_fill_amount (which is 1
        // in the orders V0 case).
        if left_to_fill >= min_non_zero_fill_amount {
            // Fill the rest of the order
            let filled_amount = calculate_fill_order(&tf, &order_id, left_to_fill, version);

            let fill_order_input = match version {
                OrdersVersion::V0 => TxInput::AccountCommand(
                    AccountNonce::new(1),
                    AccountCommand::FillOrder(order_id, left_to_fill, Destination::AnyoneCanSpend),
                ),
                OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id,
                    left_to_fill,
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

            let expected_give_balance = match version {
                OrdersVersion::V0 => None,
                OrdersVersion::V1 => {
                    let filled1 = (give_amount.into_atoms() * fill_amount.into_atoms())
                        / ask_amount.into_atoms();
                    let filled2 = (give_amount.into_atoms() * left_to_fill.into_atoms())
                        / ask_amount.into_atoms();
                    let remainder = (give_amount - Amount::from_atoms(filled1 + filled2))
                        .unwrap()
                        .as_non_zero();
                    remainder
                }
            };

            assert_order_exists(
                &tf,
                &mut rng,
                &order_id,
                &ExpectedOrderData {
                    initial_data: order_data.clone(),
                    ask_balance: None,
                    give_balance: expected_give_balance,
                    nonce: version.v0_then_some(AccountNonce::new(1)),
                    is_frozen: false,
                },
                true,
            );
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_then_conclude(#[case] seed: Seed, #[case] version: OrdersVersion) {
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

        // Fill the order partially or completely
        let min_fill_amount = order_min_non_zero_fill_amount(&tf, &order_id, version);
        let fill_amount = Amount::from_atoms(
            rng.gen_range(min_fill_amount.into_atoms()..=ask_amount.into_atoms()),
        );
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

        assert_order_missing(&tf, &order_id, true);

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

        assert_order_missing(&tf, &order_id, true);
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

        // Fill the order partially, leaving at least one atom unfilled (so that the expected
        // remaining ask/give amounts are always Some).
        let min_fill_amount = order_min_non_zero_fill_amount(&tf, &order_id, version);
        let fill_amount = Amount::from_atoms(
            rng.gen_range(min_fill_amount.into_atoms()..ask_amount.into_atoms()),
        );
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

        let expected_order_data = ExpectedOrderData {
            initial_data: order_data,
            ask_balance: Some(left_to_fill),
            give_balance: Some((give_amount - filled_amount).unwrap()),
            nonce: version.v0_then_some(AccountNonce::new(0)),
            is_frozen: false,
        };

        assert_order_exists(&tf, &mut rng, &order_id, &expected_order_data, true);

        // Create alternative chain and trigger the reorg
        let new_best_block =
            tf.create_chain_with_empty_blocks(&reorg_common_ancestor, 3, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), new_best_block);

        assert_order_missing(&tf, &order_id, true);

        // Reapply txs again
        tf.make_block_builder()
            .with_transactions(vec![create_order_tx, fill_order_tx])
            .build_and_process(&mut rng)
            .unwrap();

        assert_order_exists(&tf, &mut rng, &order_id, &expected_order_data, true);
    });
}

// Create a chain with an order which is filled partially or completely and then concluded.
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

        // Fill the order partially or completely
        let min_fill_amount = order_min_non_zero_fill_amount(&tf, &order_id, version);
        let fill_amount = Amount::from_atoms(
            rng.gen_range(min_fill_amount.into_atoms()..=ask_amount.into_atoms()),
        );
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

        assert_order_missing(&tf, &order_id, true);

        // Create alternative chain and trigger the reorg
        let new_best_block =
            tf.create_chain_with_empty_blocks(&reorg_common_ancestor, 3, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), new_best_block);

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data.clone(),
                ask_balance: Some(output_value_amount(order_data.ask())),
                give_balance: Some(output_value_amount(order_data.give())),
                nonce: None,
                is_frozen: false,
            },
            true,
        );

        // Reapply txs again
        tf.make_block_builder()
            .with_transactions(vec![fill_order_tx, conclude_order_tx])
            .build_and_process(&mut rng)
            .unwrap();

        assert_order_missing(&tf, &order_id, true);
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

        let genesis_utxo = UtxoOutPoint::new(tf.genesis().get_id().into(), 0);

        // Issue an NFT
        let (token_id, nft_outpoint, coins_outpoint) =
            issue_random_nft_from_best_block(&mut rng, &mut tf, genesis_utxo);

        // Create order selling NFT for coins
        let ask_amount = Amount::from_atoms(rng.gen_range(1u128..1000));
        let give_amount = Amount::from_atoms(1);
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data.clone(),
                ask_balance: Some(ask_amount),
                give_balance: Some(give_amount),
                nonce: None,
                is_frozen: false,
            },
            true,
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
                    TxInput::Utxo(coins_outpoint.clone()),
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
                        TxInput::Utxo(coins_outpoint),
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: None,
                give_balance: None,
                nonce: version.v0_then_some(AccountNonce::new(0)),
                is_frozen: false,
            },
            true,
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

        let genesis_utxo = UtxoOutPoint::new(tf.genesis().get_id().into(), 0);

        // Issue an NFT
        let (token_id, nft_outpoint, coins_outpoint) =
            issue_random_nft_from_best_block(&mut rng, &mut tf, genesis_utxo);

        // Create order selling NFT for coins
        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount = Amount::from_atoms(1);
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data.clone(),
                ask_balance: Some(ask_amount),
                give_balance: Some(give_amount),
                nonce: None,
                is_frozen: false,
            },
            true,
        );

        // Try get an nft out of order with 1 atom less
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::Utxo(coins_outpoint.clone()),
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
                TxInput::Utxo(coins_outpoint),
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data.clone(),
                ask_balance: Some(Amount::from_atoms(1)),
                give_balance: Some(give_amount),
                nonce: Some(AccountNonce::new(0)),
                is_frozen: false,
            },
            true,
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: None,
                give_balance: None,
                nonce: Some(AccountNonce::new(1)),
                is_frozen: false,
            },
            true,
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

        let genesis_utxo = UtxoOutPoint::new(tf.genesis().get_id().into(), 0);

        // Issue an NFT
        let (token_id, nft_outpoint, coins_outpoint) =
            issue_random_nft_from_best_block(&mut rng, &mut tf, genesis_utxo);

        // Create order selling NFT for coins
        let ask_amount = Amount::from_atoms(rng.gen_range(10u128..1000));
        let give_amount = Amount::from_atoms(1);
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(nft_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data.clone())))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data.clone(),
                ask_balance: Some(ask_amount),
                give_balance: Some(give_amount),
                nonce: None,
                is_frozen: false,
            },
            true,
        );

        // Try to get nft by filling order with 1 atom less, getting 0 nfts
        {
            let underbid_amount = (ask_amount - Amount::from_atoms(1)).unwrap();
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::Utxo(coins_outpoint.clone()),
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
                        TxInput::Utxo(coins_outpoint),
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: None,
                give_balance: None,
                nonce: None,
                is_frozen: false,
            },
            true,
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
                assert_order_exists(
                    &tf,
                    &mut rng,
                    &order_id,
                    &ExpectedOrderData {
                        initial_data: order_data,
                        ask_balance: Some(ask_amount),
                        give_balance: Some(give_amount),
                        nonce: Some(AccountNonce::new(0)),
                        is_frozen: false,
                    },
                    true,
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
                assert_order_exists(
                    &tf,
                    &mut rng,
                    &order_id,
                    &ExpectedOrderData {
                        initial_data: order_data,
                        ask_balance: Some(expected_ask_balance),
                        give_balance: Some(give_amount),
                        nonce: Some(AccountNonce::new(0)),
                        is_frozen: false,
                    },
                    true,
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: None,
                give_balance: Some(Amount::from_atoms(1)),
                nonce: None,
                is_frozen: false,
            },
            true,
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

        // Try to fill order before activation, expect an error
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

        // Try to conclude order before activation, expect an error
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

        // Try to fill order with deprecated command, expect an error
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

        // Try to conclude order with deprecated command, expect an error
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

        assert_order_missing(&tf, &order_id, true);
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

                assert_order_exists(
                    &tf,
                    &mut rng,
                    &order_id,
                    &ExpectedOrderData {
                        initial_data: order_data,
                        ask_balance: Some(ask_amount),
                        give_balance: Some(give_amount),
                        nonce: None,
                        is_frozen: true,
                    },
                    true,
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

        // Fill the order partially or completely
        let min_fill_amount = order_min_non_zero_fill_amount(&tf, &order_id, OrdersVersion::V1);
        let fill_amount = Amount::from_atoms(
            rng.gen_range(min_fill_amount.into_atoms()..=ask_amount.into_atoms()),
        );
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

        // Try freezing the order once more
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: Some(expected_ask_balance),
                give_balance: Some(expected_give_balance),
                nonce: Some(AccountNonce::new(2)),
                is_frozen: false,
            },
            true,
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

        let min_fill_amount = order_min_non_zero_fill_amount(&tf, &order_id, OrdersVersion::V1);
        let fill_amount = Amount::from_atoms(
            rng.gen_range(min_fill_amount.into_atoms()..initial_ask_amount.into_atoms() / 10),
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: Some(expected_ask_balance),
                give_balance: Some(expected_give_balance),
                nonce: None,
                is_frozen: false,
            },
            true,
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
#[trace]
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

        let min_fill_amount = order_min_non_zero_fill_amount(&tf, &order_id, version);
        let fill_amount1 = Amount::from_atoms(
            rng.gen_range(min_fill_amount.into_atoms()..initial_ask_amount.into_atoms() / 3),
        );
        let fill_amount2 = if use_same_amount {
            fill_amount1
        } else {
            (|| {
                for _ in 0..1000 {
                    let new_amount = Amount::from_atoms(rng.gen_range(
                        min_fill_amount.into_atoms()..initial_ask_amount.into_atoms() / 3,
                    ));
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

        assert_order_exists(
            &tf,
            &mut rng,
            &order_id,
            &ExpectedOrderData {
                initial_data: order_data,
                ask_balance: Some(expected_ask_balance),
                give_balance: Some(expected_give_balance),
                nonce: version.v0_then_some(AccountNonce::new(1)),
                is_frozen: false,
            },
            true,
        );
    });
}

// Create and (optionally) partially fill an order.
// Then conclude it, while creating another order in the same tx, with balances equal to the
// remaining balances of the original order.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conclude_and_recreate_in_same_tx_with_same_balances(
    #[case] seed: Seed,
    #[values(false, true)] fill_after_creation: bool,
) {
    utils::concurrency::model(move || {
        let version = OrdersVersion::V1;
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let tokens_amount = Amount::from_atoms(rng.gen_range(1000..1_000_000));
        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_amount_from_genesis(&mut rng, &mut tf, tokens_amount);
        let coins_amount = tf.coin_amount_from_utxo(&coins_outpoint);

        let orig_ask_amount = Amount::from_atoms(rng.gen_range(10u128..10_000));
        let orig_give_amount =
            Amount::from_atoms(rng.gen_range(10u128..=tokens_amount.into_atoms() / 2));
        let tokens_amount_after_order_creation = (tokens_amount - orig_give_amount).unwrap();

        let orig_order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(orig_ask_amount),
            OutputValue::TokenV1(token_id, orig_give_amount),
        );
        let (orig_order_id, orig_order_creation_tx_id) = {
            let tx = TransactionBuilder::new()
                .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
                .add_output(TxOutput::CreateOrder(Box::new(orig_order_data.clone())))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, tokens_amount_after_order_creation),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let order_id = make_order_id(tx.inputs()).unwrap();
            let tx_id = tx.transaction().get_id();
            tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

            (order_id, tx_id)
        };
        let tokens_outpoint = UtxoOutPoint::new(orig_order_creation_tx_id.into(), 1);
        let tokens_amount = tokens_amount_after_order_creation;

        let (fill_amount, filled_amount, coins_outpoint, coins_amount) = if fill_after_creation {
            // Fill the order partially.
            let min_fill_amount = order_min_non_zero_fill_amount(&tf, &orig_order_id, version);
            let fill_amount = Amount::from_atoms(
                rng.gen_range(min_fill_amount.into_atoms()..orig_ask_amount.into_atoms()),
            );
            let filled_amount = calculate_fill_order(&tf, &orig_order_id, fill_amount, version);
            let coins_amount_after_fill = (coins_amount - fill_amount).unwrap();

            let tx = TransactionBuilder::new()
                .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        orig_order_id,
                        fill_amount,
                    )),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, filled_amount),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(coins_amount_after_fill),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let tx_id = tx.transaction().get_id();
            tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

            let coins_outpoint = UtxoOutPoint::new(tx_id.into(), 1);
            let coins_amount = coins_amount_after_fill;

            (fill_amount, filled_amount, coins_outpoint, coins_amount)
        } else {
            (Amount::ZERO, Amount::ZERO, coins_outpoint, coins_amount)
        };

        let remaining_tokens_amount_to_trade = (orig_give_amount - filled_amount).unwrap();
        let remaining_coins_amount_to_trade = (orig_ask_amount - fill_amount).unwrap();

        let new_order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(remaining_coins_amount_to_trade),
            OutputValue::TokenV1(token_id, remaining_tokens_amount_to_trade),
        );

        // Try concluding the order and creating a new one, using only the conclusion account
        // command as an input.
        // This will fail, because order creation needs at least one UTXO input.
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(orig_order_id)),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(fill_amount),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::CreateOrder(Box::new(new_order_data.clone())))
                .build();
            let err = tf
                .make_block_builder()
                .add_transaction(tx)
                .build_and_process(&mut rng)
                .unwrap_err();
            assert_eq!(
                err,
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::IdCreationError(
                        IdCreationError::NoUtxoInputsForOrderIdCreation
                    )
                ))
            );
        }

        // Check the original order data - it's still there
        assert_order_exists(
            &tf,
            &mut rng,
            &orig_order_id,
            &ExpectedOrderData {
                initial_data: orig_order_data,
                ask_balance: Some(remaining_coins_amount_to_trade),
                give_balance: Some(remaining_tokens_amount_to_trade),
                nonce: None,
                is_frozen: false,
            },
            true,
        );

        let new_order_id = {
            let tx_builder = TransactionBuilder::new()
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(orig_order_id)),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(fill_amount),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::CreateOrder(Box::new(new_order_data.clone())));
            // Add coins or tokens to inputs and transfer the same amount in outputs.
            let tx_builder = if rng.gen_bool(0.5) {
                tx_builder
                    .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, tokens_amount),
                        Destination::AnyoneCanSpend,
                    ))
            } else {
                tx_builder
                    .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(coins_amount),
                        Destination::AnyoneCanSpend,
                    ))
            };
            let tx = tx_builder.build();
            let order_id = make_order_id(tx.inputs()).unwrap();
            tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
            order_id
        };

        // The original order is no longer there
        assert_order_missing(&tf, &orig_order_id, false);

        // The new order exists and has the same balances as the original one before the conclusion.
        assert_order_exists(
            &tf,
            &mut rng,
            &new_order_id,
            &ExpectedOrderData {
                initial_data: new_order_data,
                ask_balance: Some(remaining_coins_amount_to_trade),
                give_balance: Some(remaining_tokens_amount_to_trade),
                nonce: None,
                is_frozen: false,
            },
            true,
        );
    });
}

// Create and (optionally) fill an order; the fill may be a complete fill if the give balance
// is supposed to be increased on the next step, otherwise it'll always be a partial fill.
// Then conclude the order, while creating another one in the same tx, with balances different
// from the remaining balances of the original order.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conclude_and_recreate_in_same_tx_with_different_balances(
    #[case] seed: Seed,
    #[values(false, true)] fill_after_creation: bool,
    #[values(false, true)] increase_give_balance: bool,
) {
    utils::concurrency::model(move || {
        let version = OrdersVersion::V1;
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let tokens_amount = Amount::from_atoms(rng.gen_range(1000..1_000_000));
        let (token_id, tokens_outpoint, coins_outpoint) =
            issue_and_mint_token_amount_from_genesis(&mut rng, &mut tf, tokens_amount);
        let coins_amount = tf.coin_amount_from_utxo(&coins_outpoint);

        let orig_ask_amount = Amount::from_atoms(rng.gen_range(10u128..10_000));
        let orig_give_amount =
            Amount::from_atoms(rng.gen_range(10u128..=tokens_amount.into_atoms() / 2));
        let tokens_amount_after_order_creation = (tokens_amount - orig_give_amount).unwrap();

        let orig_order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(orig_ask_amount),
            OutputValue::TokenV1(token_id, orig_give_amount),
        );
        let (orig_order_id, orig_order_creation_tx_id) = {
            let tx = TransactionBuilder::new()
                .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
                .add_output(TxOutput::CreateOrder(Box::new(orig_order_data.clone())))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, tokens_amount_after_order_creation),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let order_id = make_order_id(tx.inputs()).unwrap();
            let tx_id = tx.transaction().get_id();
            tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

            (order_id, tx_id)
        };
        let tokens_outpoint = UtxoOutPoint::new(orig_order_creation_tx_id.into(), 1);
        let tokens_amount = tokens_amount_after_order_creation;

        let (fill_amount, filled_amount) = if fill_after_creation {
            let fill_amount = if increase_give_balance && rng.gen_bool(0.5) {
                // Fill the order completely.
                orig_ask_amount
            } else {
                // Fill the order partially.
                let min_fill_amount = order_min_non_zero_fill_amount(&tf, &orig_order_id, version);
                Amount::from_atoms(
                    rng.gen_range(min_fill_amount.into_atoms()..orig_ask_amount.into_atoms()),
                )
            };
            let filled_amount = calculate_fill_order(&tf, &orig_order_id, fill_amount, version);
            let coins_amount_after_fill = (coins_amount - fill_amount).unwrap();

            let tx = TransactionBuilder::new()
                .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                        orig_order_id,
                        fill_amount,
                    )),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, filled_amount),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(coins_amount_after_fill),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

            (fill_amount, filled_amount)
        } else {
            (Amount::ZERO, Amount::ZERO)
        };

        let remaining_tokens_amount_to_trade = (orig_give_amount - filled_amount).unwrap();
        let remaining_coins_amount_to_trade = (orig_ask_amount - fill_amount).unwrap();

        let new_tokens_amount_to_trade = if increase_give_balance {
            (remaining_tokens_amount_to_trade
                + Amount::from_atoms(rng.gen_range(1u128..tokens_amount.into_atoms())))
            .unwrap()
        } else {
            Amount::from_atoms(rng.gen_range(1..=remaining_tokens_amount_to_trade.into_atoms()))
        };

        let new_coins_amount_to_trade = Amount::from_atoms(
            rng.gen_range(1..=remaining_coins_amount_to_trade.into_atoms() * 2 + 100),
        );

        let new_order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(new_coins_amount_to_trade),
            OutputValue::TokenV1(token_id, new_tokens_amount_to_trade),
        );

        let new_order_id = {
            let tokens_atoms_change = new_tokens_amount_to_trade.into_atoms() as i128
                - remaining_tokens_amount_to_trade.into_atoms() as i128;

            let tx = TransactionBuilder::new()
                .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
                .add_input(
                    TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(orig_order_id)),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(fill_amount),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::CreateOrder(Box::new(new_order_data.clone())))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(
                        token_id,
                        Amount::from_atoms(
                            (tokens_amount.into_atoms() as i128 - tokens_atoms_change) as u128,
                        ),
                    ),
                    Destination::AnyoneCanSpend,
                ))
                .build();

            let order_id = make_order_id(tx.inputs()).unwrap();
            tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
            order_id
        };

        // The original order is no longer there
        assert_order_missing(&tf, &orig_order_id, false);

        // The new order exists with the correct balances.
        assert_order_exists(
            &tf,
            &mut rng,
            &new_order_id,
            &ExpectedOrderData {
                initial_data: new_order_data,
                ask_balance: Some(new_coins_amount_to_trade),
                give_balance: Some(new_tokens_amount_to_trade),
                nonce: None,
                is_frozen: false,
            },
            true,
        );
    });
}

// Test get_orders_info_for_rpc_by_currencies when multiple orders are available.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_orders_info_for_rpc_by_currencies_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // Create 2 fungible tokens and 2 NFTs

        let token1_mint_amount = Amount::from_atoms(rng.gen_range(1000..100_000));
        let (token1_id, token1_utxo, coins_utxo) =
            issue_and_mint_token_amount_from_genesis(&mut rng, &mut tf, token1_mint_amount);

        let token2_mint_amount = Amount::from_atoms(rng.gen_range(1000..100_000));
        let (token2_id, _, coins_utxo) = issue_and_mint_token_amount_from_best_block(
            &mut rng,
            &mut tf,
            coins_utxo,
            token2_mint_amount,
        );

        let (nft1_id, nft1_utxo, coins_utxo) =
            issue_random_nft_from_best_block(&mut rng, &mut tf, coins_utxo);

        let (nft2_id, nft2_utxo, coins_utxo) =
            issue_random_nft_from_best_block(&mut rng, &mut tf, coins_utxo);

        let coins_change_amount = tf.coin_amount_from_utxo(&coins_utxo);

        // Now create the orders; we won't be doing anything with them in this test,
        // so all non-initial data will have the default values.

        fn make_expected_order_info(initial_data: &OrderData) -> RpcOrderInfo {
            RpcOrderInfo {
                conclude_key: initial_data.conclude_key().clone(),
                initially_asked: RpcOutputValue::from_output_value(initial_data.ask()).unwrap(),
                initially_given: RpcOutputValue::from_output_value(initial_data.give()).unwrap(),
                ask_balance: initial_data.ask().amount(),
                give_balance: initial_data.give().amount(),
                nonce: None,
                is_frozen: false,
            }
        }

        // Create order 1, which gives token1 for coins

        let order1_coin_ask_amount = Amount::from_atoms(rng.gen_range(100..200));
        let order1_token1_give_amount = Amount::from_atoms(rng.gen_range(100..200));

        let token1_change_amount = (token1_mint_amount - order1_token1_give_amount).unwrap();
        let order1_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(order1_coin_ask_amount),
            OutputValue::TokenV1(token1_id, order1_token1_give_amount),
        );
        let order1_expected_info = make_expected_order_info(&order1_data);
        let order1_tx = TransactionBuilder::new()
            .add_input(token1_utxo.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order1_data)))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token1_id, token1_change_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token1_utxo = UtxoOutPoint::new(order1_tx.transaction().get_id().into(), 1);
        let order1_id = make_order_id(order1_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order1_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order 2, which gives NFT1 for coins

        let order2_coin_ask_amount = Amount::from_atoms(rng.gen_range(100..200));

        let order2_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(order2_coin_ask_amount),
            OutputValue::TokenV1(nft1_id, Amount::from_atoms(1)),
        );
        let order2_expected_info = make_expected_order_info(&order2_data);
        let order2_tx = TransactionBuilder::new()
            .add_input(nft1_utxo.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order2_data)))
            .build();
        let order2_id = make_order_id(order2_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order2_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order 3, which gives NFT2 for token2

        let order3_token2_ask_amount = Amount::from_atoms(rng.gen_range(100..200));

        let order3_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(token2_id, order3_token2_ask_amount),
            OutputValue::TokenV1(nft2_id, Amount::from_atoms(1)),
        );
        let order3_expected_info = make_expected_order_info(&order3_data);
        let order3_tx = TransactionBuilder::new()
            .add_input(nft2_utxo.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order3_data)))
            .build();
        let order3_id = make_order_id(order3_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order3_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order 4, which gives token1 for NFT1

        let order4_token1_give_amount = Amount::from_atoms(rng.gen_range(100..200));

        let token1_change_amount = (token1_change_amount - order4_token1_give_amount).unwrap();
        let order4_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(nft1_id, Amount::from_atoms(1)),
            OutputValue::TokenV1(token1_id, order4_token1_give_amount),
        );
        let order4_expected_info = make_expected_order_info(&order4_data);
        let order4_tx = TransactionBuilder::new()
            .add_input(token1_utxo.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order4_data)))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token1_id, token1_change_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token1_utxo = UtxoOutPoint::new(order4_tx.transaction().get_id().into(), 1);
        let order4_id = make_order_id(order4_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order4_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order 5, which gives coins for NFT2

        let order5_coins_give_amount = Amount::from_atoms(rng.gen_range(100..200));
        let coins_change_amount = (coins_change_amount - order5_coins_give_amount).unwrap();

        let order5_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(nft2_id, Amount::from_atoms(1)),
            OutputValue::Coin(order5_coins_give_amount),
        );
        let order5_expected_info = make_expected_order_info(&order5_data);
        let order5_tx = TransactionBuilder::new()
            .add_input(coins_utxo.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order5_data)))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(coins_change_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let coins_utxo = UtxoOutPoint::new(order5_tx.transaction().get_id().into(), 1);
        let order5_id = make_order_id(order5_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order5_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order 6, which gives token1 for token2

        let order6_token2_ask_amount = Amount::from_atoms(rng.gen_range(100..200));
        let order6_token1_give_amount = Amount::from_atoms(rng.gen_range(100..200));

        let token1_change_amount = (token1_change_amount - order6_token1_give_amount).unwrap();
        let order6_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(token2_id, order6_token2_ask_amount),
            OutputValue::TokenV1(token1_id, order6_token1_give_amount),
        );
        let order6_expected_info = make_expected_order_info(&order6_data);
        let order6_tx = TransactionBuilder::new()
            .add_input(token1_utxo.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order6_data)))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token1_id, token1_change_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let order6_id = make_order_id(order6_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order6_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Create order 7, which gives coins for token2

        let order7_token2_ask_amount = Amount::from_atoms(rng.gen_range(100..200));
        let order7_coins_give_amount = Amount::from_atoms(rng.gen_range(100..200));

        let coins_change_amount = (coins_change_amount - order7_coins_give_amount).unwrap();
        let order7_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(token2_id, order7_token2_ask_amount),
            OutputValue::Coin(order7_coins_give_amount),
        );
        let order7_expected_info = make_expected_order_info(&order7_data);
        let order7_tx = TransactionBuilder::new()
            .add_input(coins_utxo.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order7_data)))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(coins_change_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let order7_id = make_order_id(order7_tx.inputs()).unwrap();
        tf.make_block_builder()
            .add_transaction(order7_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Now we have:
        // 2 orders that ask for coins - orders 1 and 2;
        // 3 orders that ask for token2 - orders 3, 6 and 7;
        // 1 order that asks for NFT1 - order 4;
        // 1 order that asks for NFT2 - order 5;
        // 2 orders that give coins - orders 5 and 7;
        // 3 orders that give token1 - orders 1, 4 and 6;
        // 1 order that gives NFT1 - order 2;
        // 1 order that gives NFT2 - order 3;

        let check_ask = |ask_currency, expected_infos| {
            let actual_infos = tf
                .chainstate
                .get_orders_info_for_rpc_by_currencies(Some(&ask_currency), None)
                .unwrap();
            assert_eq!(actual_infos, expected_infos);
        };

        let check_give = |give_currency, expected_infos| {
            let actual_infos = tf
                .chainstate
                .get_orders_info_for_rpc_by_currencies(None, Some(&give_currency))
                .unwrap();
            assert_eq!(actual_infos, expected_infos);
        };

        let check_both = |ask_currency, give_currency, expected_infos| {
            let actual_infos = tf
                .chainstate
                .get_orders_info_for_rpc_by_currencies(Some(&ask_currency), Some(&give_currency))
                .unwrap();
            assert_eq!(actual_infos, expected_infos);
        };

        // Use unqualified names of the currencies to prevent rustfmt from turning a one-liner check
        // into 5 lines (note that having a shorter alias like Curr doesn't always help).
        use Currency::*;

        // Get all orders
        {
            let expected_infos = BTreeMap::from_iter([
                (order1_id, order1_expected_info.clone()),
                (order2_id, order2_expected_info.clone()),
                (order3_id, order3_expected_info.clone()),
                (order4_id, order4_expected_info.clone()),
                (order5_id, order5_expected_info.clone()),
                (order6_id, order6_expected_info.clone()),
                (order7_id, order7_expected_info.clone()),
            ]);
            let actual_infos =
                tf.chainstate.get_orders_info_for_rpc_by_currencies(None, None).unwrap();
            assert_eq!(actual_infos, expected_infos);
        }

        // Check currencies that are never given or asked for
        {
            // No one asks for token1
            check_ask(Token(token1_id), BTreeMap::new());
            check_both(Token(token1_id), Coin, BTreeMap::new());
            check_both(Token(token1_id), Token(token1_id), BTreeMap::new());
            check_both(Token(token1_id), Token(token2_id), BTreeMap::new());
            check_both(Token(token1_id), Token(nft1_id), BTreeMap::new());
            check_both(Token(token1_id), Token(nft2_id), BTreeMap::new());

            // No one gives token2
            check_give(Token(token2_id), BTreeMap::new());
            check_both(Coin, Token(token2_id), BTreeMap::new());
            check_both(Token(token1_id), Token(token2_id), BTreeMap::new());
            check_both(Token(token2_id), Token(token2_id), BTreeMap::new());
            check_both(Token(nft1_id), Token(token2_id), BTreeMap::new());
            check_both(Token(nft2_id), Token(token2_id), BTreeMap::new());
        }

        // Get all orders that ask for a specific currency.
        {
            // Get all orders that ask for coins
            let expected_infos = BTreeMap::from_iter([
                (order1_id, order1_expected_info.clone()),
                (order2_id, order2_expected_info.clone()),
            ]);
            check_ask(Coin, expected_infos);

            // Get all orders that ask for token2
            let expected_infos = BTreeMap::from_iter([
                (order3_id, order3_expected_info.clone()),
                (order6_id, order6_expected_info.clone()),
                (order7_id, order7_expected_info.clone()),
            ]);
            check_ask(Token(token2_id), expected_infos);

            // Get all orders that ask for NFT1
            let expected_infos = BTreeMap::from_iter([(order4_id, order4_expected_info.clone())]);
            check_ask(Token(nft1_id), expected_infos);

            // Get all orders that ask for NFT2
            let expected_infos = BTreeMap::from_iter([(order5_id, order5_expected_info.clone())]);
            check_ask(Token(nft2_id), expected_infos);
        }

        // Get all orders that give specific currency.
        {
            // Get all orders that give coins
            let expected_infos = BTreeMap::from_iter([
                (order5_id, order5_expected_info.clone()),
                (order7_id, order7_expected_info.clone()),
            ]);
            check_give(Coin, expected_infos);

            // Get all orders that give token1
            let expected_infos = BTreeMap::from_iter([
                (order1_id, order1_expected_info.clone()),
                (order4_id, order4_expected_info.clone()),
                (order6_id, order6_expected_info.clone()),
            ]);
            check_give(Token(token1_id), expected_infos);

            // Get all orders that give NFT1
            let expected_infos = BTreeMap::from_iter([(order2_id, order2_expected_info.clone())]);
            check_give(Token(nft1_id), expected_infos);

            // Get all orders that give NFT2
            let expected_infos = BTreeMap::from_iter([(order3_id, order3_expected_info.clone())]);
            check_give(Token(nft2_id), expected_infos);
        }

        // Get all orders with specific give/ask currencies.
        {
            // Asking for coins

            // Get all orders that ask for coins and give coins
            check_both(Coin, Coin, BTreeMap::new());

            // Get all orders that ask for coins and give token1
            let expected_infos = BTreeMap::from_iter([(order1_id, order1_expected_info.clone())]);
            check_both(Coin, Token(token1_id), expected_infos);

            // Get all orders that ask for coins and give NFT1
            let expected_infos = BTreeMap::from_iter([(order2_id, order2_expected_info.clone())]);
            check_both(Coin, Token(nft1_id), expected_infos);

            // Get all orders that ask for coins and give NFT2
            check_both(Coin, Token(nft2_id), BTreeMap::new());

            // Asking for token2

            // Get all orders that ask for token2 and give coins
            let expected_infos = BTreeMap::from_iter([(order7_id, order7_expected_info.clone())]);
            check_both(Token(token2_id), Coin, expected_infos);

            // Get all orders that ask for token2 and give token1
            let expected_infos = BTreeMap::from_iter([(order6_id, order6_expected_info.clone())]);
            check_both(Token(token2_id), Token(token1_id), expected_infos);

            // Get all orders that ask for token2 and give NFT1
            check_both(Token(token2_id), Token(nft1_id), BTreeMap::new());

            // Get all orders that ask for token2 and give NFT2
            let expected_infos = BTreeMap::from_iter([(order3_id, order3_expected_info.clone())]);
            check_both(Token(token2_id), Token(nft2_id), expected_infos);

            // Asking for NFT1

            // Get all orders that ask for NFT1 and give coins
            check_both(Token(nft1_id), Coin, BTreeMap::new());

            // Get all orders that ask for NFT1 and give token1
            let expected_infos = BTreeMap::from_iter([(order4_id, order4_expected_info.clone())]);
            check_both(Token(nft1_id), Token(token1_id), expected_infos);

            // Get all orders that ask for NFT1 and give NFT1
            check_both(Token(nft1_id), Token(nft1_id), BTreeMap::new());

            // Get all orders that ask for NFT1 and give NFT2
            check_both(Token(nft1_id), Token(nft2_id), BTreeMap::new());

            // Asking for NFT2

            // Get all orders that ask for NFT2 and give coins
            let expected_infos = BTreeMap::from_iter([(order5_id, order5_expected_info.clone())]);
            check_both(Token(nft2_id), Coin, expected_infos);

            // Get all orders that ask for NFT2 and give token1
            check_both(Token(nft2_id), Token(token1_id), BTreeMap::new());

            // Get all orders that ask for NFT2 and give NFT1
            check_both(Token(nft2_id), Token(nft1_id), BTreeMap::new());

            // Get all orders that ask for NFT2 and give NFT2
            check_both(Token(nft2_id), Token(nft2_id), BTreeMap::new());
        }
    });
}

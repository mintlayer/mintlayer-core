// Copyright (c) 2021-2025 RBB S.r.l
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

use chainstate::{
    constraints_value_accumulator, tx_verifier::error::InputCheckErrorPayload,
    ConnectTransactionError,
};
use chainstate_test_framework::{
    helpers::{
        calculate_fill_order, issue_and_mint_random_token_from_best_block,
        make_tx_builder_to_split_utxo, split_utxo,
    },
    TestFrameworkBuilder,
};
use common::chain::{
    make_order_id,
    tokens::{IsTokenFreezable, TokenId, TokenTotalSupply},
    ChainstateUpgradeBuilder, OrderAccountCommand, OrderData, OrderId, OrdersVersion, UtxoOutPoint,
};
use mintscript::translate::TranslationError;
use test_utils::{assert_matches, assert_matches_return_val};

use super::*;

use crate::error::TxValidationError;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_orphans(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = create_test_framework_builder_with_orders_v1(&mut rng).build();

    let (token_id, tokens_outpoint, coins_outpoint) =
        issue_and_mint_token_from_genesis(&mut rng, &mut tf);

    let tokens_src_id: OutPointSourceId = split_utxo(&mut rng, &mut tf, tokens_outpoint, 2).into();
    let coins_src_id: OutPointSourceId = split_utxo(&mut rng, &mut tf, coins_outpoint, 10).into();

    let initial_ask_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let initial_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let order_id = {
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(initial_ask_amount),
            OutputValue::TokenV1(token_id, initial_give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(tokens_src_id.clone(), 0).into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
        order_id
    };
    let another_order_initial_ask_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let another_order_initial_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let another_order_id = {
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(another_order_initial_ask_amount),
            OutputValue::TokenV1(token_id, another_order_initial_give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(tokens_src_id.clone(), 1).into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
        order_id
    };

    let fill_tx1 = make_fill_order_tx(
        &mut tf,
        order_id,
        token_id,
        Amount::from_atoms(rng.gen_range(10..initial_ask_amount.into_atoms() / 10)),
        UtxoOutPoint::new(coins_src_id.clone(), 0),
        None,
    );
    let fill_tx2 = make_fill_order_tx(
        &mut tf,
        order_id,
        token_id,
        Amount::from_atoms(rng.gen_range(10..initial_ask_amount.into_atoms() / 10)),
        UtxoOutPoint::new(coins_src_id.clone(), 1),
        None,
    );
    let fill_tx3 = make_fill_order_tx(
        &mut tf,
        order_id,
        token_id,
        Amount::from_atoms(rng.gen_range(10..initial_ask_amount.into_atoms() / 10)),
        UtxoOutPoint::new(coins_src_id.clone(), 2),
        None,
    );
    let freeze_tx1 = make_freeze_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 3),
        None,
    );
    let freeze_tx2 = make_freeze_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 4),
        None,
    );
    let conclude_tx1 = make_conclude_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 5),
        None,
    );
    let conclude_tx2 = make_conclude_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 6),
        None,
    );
    let another_order_fill_tx = make_fill_order_tx(
        &mut tf,
        another_order_id,
        token_id,
        Amount::from_atoms(rng.gen_range(10..another_order_initial_ask_amount.into_atoms() / 10)),
        UtxoOutPoint::new(coins_src_id.clone(), 7),
        None,
    );
    let another_order_freeze_tx = make_freeze_order_tx(
        &mut tf,
        another_order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 8),
        None,
    );
    let another_order_conclude_tx = make_conclude_order_tx(
        &mut tf,
        another_order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 9),
        None,
    );

    let chain_config = std::sync::Arc::clone(tf.chain_config());
    let mempool_config = create_mempool_config();
    let chainstate_handle = start_chainstate(tf.chainstate());
    let create_mempool = || {
        Mempool::new(
            Arc::clone(&chain_config),
            mempool_config.clone(),
            chainstate_handle.clone(),
            Default::default(),
            StoreMemoryUsageEstimator,
        )
    };

    {
        let mut mempool = create_mempool();

        // Can add another fill tx after a fill tx.
        mempool.add_transaction_test(fill_tx1.clone()).unwrap().assert_in_mempool();
        mempool.add_transaction_test(fill_tx2.clone()).unwrap().assert_in_mempool();

        // Can add a freeze after the fills.
        mempool.add_transaction_test(freeze_tx1.clone()).unwrap().assert_in_mempool();

        // Cannot add another freeze.
        let err = mempool.add_transaction_test(freeze_tx2.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::OrdersAccountingError(
                    orders_accounting::Error::AttemptedFreezeAlreadyFrozenOrder(_)
                )
            ))
        );

        // Cannot add another fill after the freeze.
        let err = mempool.add_transaction_test(fill_tx3.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::AttemptedFillFrozenOrder(_)
                    ),
                    _
                )
            ))
        );

        // Can add a conclude tx.
        mempool.add_transaction_test(conclude_tx1.clone()).unwrap().assert_in_mempool();

        // Cannot add another conclude tx.
        let err = mempool.add_transaction_test(conclude_tx2.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );

        // Still cannot add another freeze.
        let err = mempool.add_transaction_test(freeze_tx2.clone()).unwrap_err();
        let err_payload = assert_matches_return_val!(
            &err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::InputCheck(err),
            )),
            err.error()
        );
        assert_matches!(
            err_payload,
            InputCheckErrorPayload::Translation(TranslationError::OrderNotFound(_))
        );

        // Still cannot add another fill.
        let err = mempool.add_transaction_test(fill_tx3.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );

        // Can fill/freeze/conclude another order
        mempool
            .add_transaction_test(another_order_fill_tx.clone())
            .unwrap()
            .assert_in_mempool();
        mempool
            .add_transaction_test(another_order_freeze_tx.clone())
            .unwrap()
            .assert_in_mempool();
        mempool
            .add_transaction_test(another_order_conclude_tx.clone())
            .unwrap()
            .assert_in_mempool();
    }

    // Same as above, but we start with a freeze
    {
        let mut mempool = create_mempool();

        // Can add the freeze.
        mempool.add_transaction_test(freeze_tx1.clone()).unwrap().assert_in_mempool();

        // Cannot add another freeze.
        let err = mempool.add_transaction_test(freeze_tx2.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::OrdersAccountingError(
                    orders_accounting::Error::AttemptedFreezeAlreadyFrozenOrder(_)
                )
            ))
        );

        // Cannot add a fill after the freeze.
        let err = mempool.add_transaction_test(fill_tx1.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::AttemptedFillFrozenOrder(_)
                    ),
                    _
                )
            ))
        );

        // Can add a conclude tx.
        mempool.add_transaction_test(conclude_tx1.clone()).unwrap().assert_in_mempool();

        // Cannot add another conclude tx.
        let err = mempool.add_transaction_test(conclude_tx2.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );

        // Still cannot add another freeze.
        let err = mempool.add_transaction_test(freeze_tx2.clone()).unwrap_err();
        let err_payload = assert_matches_return_val!(
            &err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::InputCheck(err),
            )),
            err.error()
        );
        assert_matches!(
            err_payload,
            InputCheckErrorPayload::Translation(TranslationError::OrderNotFound(_))
        );

        // Still cannot add another fill.
        let err = mempool.add_transaction_test(fill_tx3.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );

        // Can fill/freeze/conclude another order
        mempool
            .add_transaction_test(another_order_fill_tx.clone())
            .unwrap()
            .assert_in_mempool();
        mempool
            .add_transaction_test(another_order_freeze_tx.clone())
            .unwrap()
            .assert_in_mempool();
        mempool
            .add_transaction_test(another_order_conclude_tx.clone())
            .unwrap()
            .assert_in_mempool();
    }

    // Same as above, but we start with a conclude.
    {
        let mut mempool = create_mempool();

        // Can add the conclude tx.
        mempool.add_transaction_test(conclude_tx1.clone()).unwrap().assert_in_mempool();

        // Cannot add another conclude tx.
        let err = mempool.add_transaction_test(conclude_tx2.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );

        // Cannot add a fill after the conclude.
        let err = mempool.add_transaction_test(fill_tx1.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );

        // Cannot add a freeze after the conclude.
        let err = mempool.add_transaction_test(freeze_tx1.clone()).unwrap_err();
        let err_payload = assert_matches_return_val!(
            &err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::InputCheck(err),
            )),
            err.error()
        );
        assert_matches!(
            err_payload,
            InputCheckErrorPayload::Translation(TranslationError::OrderNotFound(_))
        );

        // Can fill/freeze/conclude another order
        mempool
            .add_transaction_test(another_order_fill_tx.clone())
            .unwrap()
            .assert_in_mempool();
        mempool
            .add_transaction_test(another_order_freeze_tx.clone())
            .unwrap()
            .assert_in_mempool();
        mempool
            .add_transaction_test(another_order_conclude_tx.clone())
            .unwrap()
            .assert_in_mempool();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orphans_with_missing_utxo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = create_test_framework_builder_with_orders_v1(&mut rng).build();

    let (token_id, tokens_outpoint, coins_outpoint) =
        issue_and_mint_token_from_genesis(&mut rng, &mut tf);

    let coins_src_id: OutPointSourceId = split_utxo(&mut rng, &mut tf, coins_outpoint, 10).into();

    let initial_ask_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let initial_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let order_id = {
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(initial_ask_amount),
            OutputValue::TokenV1(token_id, initial_give_amount),
        );

        let tx = TransactionBuilder::new()
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        let order_id = make_order_id(tx.inputs()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
        order_id
    };

    let missing_parent_tx = make_tx_builder_to_split_utxo(
        &mut rng,
        &mut tf,
        UtxoOutPoint::new(coins_src_id.clone(), 0),
        10,
        Amount::from_atoms(TEST_MIN_TX_RELAY_FEE_RATE.atoms_per_kb()),
    )
    .build();
    let missing_parent_tx_src_id: OutPointSourceId =
        missing_parent_tx.transaction().get_id().into();

    let fill_tx1 = make_fill_order_tx(
        &mut tf,
        order_id,
        token_id,
        Amount::from_atoms(rng.gen_range(10..initial_ask_amount.into_atoms() / 10)),
        UtxoOutPoint::new(coins_src_id.clone(), 1),
        Some(UtxoOutPoint::new(missing_parent_tx_src_id.clone(), 0).into()),
    );
    let fill_tx1_id = fill_tx1.transaction().get_id();
    let fill_tx2 = make_fill_order_tx(
        &mut tf,
        order_id,
        token_id,
        Amount::from_atoms(rng.gen_range(10..initial_ask_amount.into_atoms() / 10)),
        UtxoOutPoint::new(coins_src_id.clone(), 2),
        Some(UtxoOutPoint::new(missing_parent_tx_src_id.clone(), 1).into()),
    );
    let fill_tx2_id = fill_tx2.transaction().get_id();
    let freeze_tx1 = make_freeze_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 3),
        Some(UtxoOutPoint::new(missing_parent_tx_src_id.clone(), 2).into()),
    );
    let freeze_tx1_id = freeze_tx1.transaction().get_id();
    let freeze_tx2 = make_freeze_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 4),
        Some(UtxoOutPoint::new(missing_parent_tx_src_id.clone(), 3).into()),
    );
    let freeze_tx2_id = freeze_tx2.transaction().get_id();
    let conclude_tx1 = make_conclude_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 5),
        Some(UtxoOutPoint::new(missing_parent_tx_src_id.clone(), 4).into()),
    );
    let conclude_tx1_id = conclude_tx1.transaction().get_id();
    let conclude_tx2 = make_conclude_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 6),
        Some(UtxoOutPoint::new(missing_parent_tx_src_id.clone(), 5).into()),
    );
    let conclude_tx2_id = conclude_tx2.transaction().get_id();

    let unrelated_tx = TransactionBuilder::new()
        .add_input(
            UtxoOutPoint::new(coins_src_id.clone(), 7).into(),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(1))))
        .build();

    let chain_config = std::sync::Arc::clone(tf.chain_config());
    let mempool_config = create_mempool_config();
    let chainstate_handle = start_chainstate(tf.chainstate());
    let create_mempool = || {
        Mempool::new(
            Arc::clone(&chain_config),
            mempool_config.clone(),
            chainstate_handle.clone(),
            Default::default(),
            StoreMemoryUsageEstimator,
        )
    };

    // Note:
    // 1) Below we can add, say, a freeze before a fill and they both end up in the orphan pool.
    // This is because currently the orphan pool has no way of knowing whether 2 order txs can
    // conflict with each other.
    // 2) In the above-mentioned scenario, after the missing tx has been added to the mempool
    // (so that the orphan txs are no longer orphans), the fill tx may or may not end up in the
    // "normal" mempool, depending on the order in which the orphans will be handled. However,
    // in both cases it will no longer be in the orphan pool.

    // Add 2 orphan fill txs. After the missing parent is also added, both fill txs should
    // be in the mempool and none of them should be in the orphan pool.
    {
        let mut mempool = create_mempool();

        mempool.add_transaction_test(fill_tx1.clone()).unwrap().assert_in_orphan_pool();
        mempool.add_transaction_test(fill_tx2.clone()).unwrap().assert_in_orphan_pool();

        assert!(!mempool.contains_transaction(&fill_tx1_id));
        assert!(!mempool.contains_transaction(&fill_tx2_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx2_id));

        // Add an unrelated tx; this shouldn't affect the orphans.
        mempool.add_transaction_test(unrelated_tx.clone()).unwrap().assert_in_mempool();
        assert!(!mempool.contains_transaction(&fill_tx1_id));
        assert!(!mempool.contains_transaction(&fill_tx2_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx2_id));

        // Now add the missing parent.
        mempool
            .add_transaction_test(missing_parent_tx.clone())
            .unwrap()
            .assert_in_mempool();

        assert!(mempool.contains_transaction(&fill_tx1_id));
        assert!(mempool.contains_transaction(&fill_tx2_id));
        assert!(!mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(!mempool.contains_orphan_transaction(&fill_tx2_id));
    }

    // Add 2 orphan freeze and some fill txs. After the missing parent is also added, only
    // one of the freeze txs should be in the mempool; none of the txs should be in the orphan pool.
    {
        let mut mempool = create_mempool();

        mempool
            .add_transaction_test(freeze_tx1.clone())
            .unwrap()
            .assert_in_orphan_pool();
        mempool
            .add_transaction_test(freeze_tx2.clone())
            .unwrap()
            .assert_in_orphan_pool();
        mempool.add_transaction_test(fill_tx1.clone()).unwrap().assert_in_orphan_pool();
        mempool.add_transaction_test(fill_tx2.clone()).unwrap().assert_in_orphan_pool();

        assert!(!mempool.contains_transaction(&fill_tx1_id));
        assert!(!mempool.contains_transaction(&fill_tx2_id));
        assert!(!mempool.contains_transaction(&freeze_tx1_id));
        assert!(!mempool.contains_transaction(&freeze_tx2_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx2_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx1_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx2_id));

        // Add an unrelated tx; this shouldn't affect the orphans.
        mempool.add_transaction_test(unrelated_tx.clone()).unwrap().assert_in_mempool();
        assert!(!mempool.contains_transaction(&fill_tx1_id));
        assert!(!mempool.contains_transaction(&fill_tx2_id));
        assert!(!mempool.contains_transaction(&freeze_tx1_id));
        assert!(!mempool.contains_transaction(&freeze_tx2_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx2_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx1_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx2_id));

        // Now add the missing parent.
        mempool
            .add_transaction_test(missing_parent_tx.clone())
            .unwrap()
            .assert_in_mempool();

        // Only one of the freeze txs should be in the mempool.
        let freeze1_in_mempool = mempool.contains_transaction(&freeze_tx1_id);
        let freeze2_in_mempool = mempool.contains_transaction(&freeze_tx2_id);
        assert_ne!(freeze1_in_mempool, freeze2_in_mempool);

        // None of the txs should be in the orphans pool.
        assert!(!mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(!mempool.contains_orphan_transaction(&fill_tx2_id));
        assert!(!mempool.contains_orphan_transaction(&freeze_tx1_id));
        assert!(!mempool.contains_orphan_transaction(&freeze_tx2_id));
    }

    // Add 2 orphan conclude and some fill/freeze txs. After the missing parent is also added, only
    // one of the conclude txs should be in the mempool; none of the txs should be in the orphan pool.
    {
        let mut mempool = create_mempool();

        mempool
            .add_transaction_test(conclude_tx1.clone())
            .unwrap()
            .assert_in_orphan_pool();
        mempool
            .add_transaction_test(conclude_tx2.clone())
            .unwrap()
            .assert_in_orphan_pool();
        mempool
            .add_transaction_test(freeze_tx1.clone())
            .unwrap()
            .assert_in_orphan_pool();
        mempool
            .add_transaction_test(freeze_tx2.clone())
            .unwrap()
            .assert_in_orphan_pool();
        mempool.add_transaction_test(fill_tx1.clone()).unwrap().assert_in_orphan_pool();
        mempool.add_transaction_test(fill_tx2.clone()).unwrap().assert_in_orphan_pool();

        assert!(!mempool.contains_transaction(&fill_tx1_id));
        assert!(!mempool.contains_transaction(&fill_tx2_id));
        assert!(!mempool.contains_transaction(&freeze_tx1_id));
        assert!(!mempool.contains_transaction(&freeze_tx2_id));
        assert!(!mempool.contains_transaction(&conclude_tx1_id));
        assert!(!mempool.contains_transaction(&conclude_tx2_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx2_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx1_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx2_id));
        assert!(mempool.contains_orphan_transaction(&conclude_tx1_id));
        assert!(mempool.contains_orphan_transaction(&conclude_tx2_id));

        // Add an unrelated tx; this shouldn't affect the orphans.
        mempool.add_transaction_test(unrelated_tx.clone()).unwrap().assert_in_mempool();
        assert!(!mempool.contains_transaction(&fill_tx1_id));
        assert!(!mempool.contains_transaction(&fill_tx2_id));
        assert!(!mempool.contains_transaction(&freeze_tx1_id));
        assert!(!mempool.contains_transaction(&freeze_tx2_id));
        assert!(!mempool.contains_transaction(&conclude_tx1_id));
        assert!(!mempool.contains_transaction(&conclude_tx2_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(mempool.contains_orphan_transaction(&fill_tx2_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx1_id));
        assert!(mempool.contains_orphan_transaction(&freeze_tx2_id));
        assert!(mempool.contains_orphan_transaction(&conclude_tx1_id));
        assert!(mempool.contains_orphan_transaction(&conclude_tx2_id));

        // Now add the missing parent.
        mempool
            .add_transaction_test(missing_parent_tx.clone())
            .unwrap()
            .assert_in_mempool();

        // Only one of the conclude txs should be in the mempool.
        let conclude1_in_mempool = mempool.contains_transaction(&conclude_tx1_id);
        let conclude2_in_mempool = mempool.contains_transaction(&conclude_tx2_id);
        assert_ne!(conclude1_in_mempool, conclude2_in_mempool);

        // None of the txs should be in the orphans pool.
        assert!(!mempool.contains_orphan_transaction(&fill_tx1_id));
        assert!(!mempool.contains_orphan_transaction(&fill_tx2_id));
        assert!(!mempool.contains_orphan_transaction(&freeze_tx1_id));
        assert!(!mempool.contains_orphan_transaction(&freeze_tx2_id));
        assert!(!mempool.contains_orphan_transaction(&conclude_tx1_id));
        assert!(!mempool.contains_orphan_transaction(&conclude_tx2_id));
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orphans_with_missing_order(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = create_test_framework_builder_with_orders_v1(&mut rng).build();

    let (token_id, tokens_outpoint, coins_outpoint) =
        issue_and_mint_token_from_genesis(&mut rng, &mut tf);

    let coins_src_id: OutPointSourceId = split_utxo(&mut rng, &mut tf, coins_outpoint, 10).into();

    let initial_ask_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let initial_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let order_creation_tx = {
        let fee_input = UtxoOutPoint::new(coins_src_id.clone(), 0);
        let coins_amount = tf.coin_amount_from_utxo(&fee_input);
        let fee = TEST_MIN_TX_RELAY_FEE_RATE.atoms_per_kb(); // the tx is expected to be less than 1 kb
        let change = (coins_amount - Amount::from_atoms(fee)).unwrap();

        TransactionBuilder::new()
            .add_input(fee_input.into(), InputWitness::NoSignature(None))
            .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(OrderData::new(
                Destination::AnyoneCanSpend,
                OutputValue::Coin(initial_ask_amount),
                OutputValue::TokenV1(token_id, initial_give_amount),
            ))))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .build()
    };
    let order_id = make_order_id(order_creation_tx.inputs()).unwrap();

    let fill_tx = make_fill_order_tx_from_initial_amounts(
        &mut tf,
        order_id,
        token_id,
        initial_ask_amount,
        initial_give_amount,
        Amount::from_atoms(rng.gen_range(10..initial_ask_amount.into_atoms() / 10)),
        UtxoOutPoint::new(coins_src_id.clone(), 1),
        None,
    );
    let freeze_tx = make_freeze_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 2),
        None,
    );
    let conclude_tx = make_conclude_order_tx(
        &mut tf,
        order_id,
        UtxoOutPoint::new(coins_src_id.clone(), 3),
        None,
    );

    let chain_config = std::sync::Arc::clone(tf.chain_config());
    let mempool_config = create_mempool_config();
    let chainstate_handle = start_chainstate(tf.chainstate());
    let create_mempool = || {
        Mempool::new(
            Arc::clone(&chain_config),
            mempool_config.clone(),
            chainstate_handle.clone(),
            Default::default(),
            StoreMemoryUsageEstimator,
        )
    };

    // Note: at this moment missing order is considered a hard error, so the txs will just be rejected.
    {
        let mut mempool = create_mempool();

        let err = mempool.add_transaction_test(fill_tx.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );

        let err = mempool.add_transaction_test(freeze_tx.clone()).unwrap_err();
        let err_payload = assert_matches_return_val!(
            &err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::InputCheck(err),
            )),
            err.error()
        );
        assert_matches!(
            err_payload,
            InputCheckErrorPayload::Translation(TranslationError::OrderNotFound(_))
        );

        let err = mempool.add_transaction_test(conclude_tx.clone()).unwrap_err();
        assert_matches!(
            err,
            Error::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::OrdersAccountingError(
                        orders_accounting::Error::OrderDataNotFound(_)
                    ),
                    _
                )
            ))
        );
    }
}

fn create_test_framework_builder_with_orders_v1(
    rng: &mut (impl Rng + CryptoRng),
) -> TestFrameworkBuilder {
    TestFramework::builder(rng).with_chain_config(
        common::chain::config::Builder::test_chain()
            .chainstate_upgrades(
                common::chain::NetUpgrades::initialize(vec![(
                    BlockHeight::zero(),
                    ChainstateUpgradeBuilder::latest().orders_version(OrdersVersion::V1).build(),
                )])
                .unwrap(),
            )
            .build(),
    )
}

fn issue_and_mint_token_from_genesis(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> (TokenId, UtxoOutPoint, UtxoOutPoint) {
    let genesis_block_id = tf.genesis().get_id();
    let utxo = UtxoOutPoint::new(genesis_block_id.into(), 0);
    let to_mint = Amount::from_atoms(rng.gen_range(100..100_000_000));

    issue_and_mint_random_token_from_best_block(
        rng,
        tf,
        utxo,
        to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    )
}

fn make_fill_order_tx(
    tf: &mut TestFramework,
    order_id: OrderId,
    token_id: TokenId,
    fill_amount: Amount,
    coins_outpoint: UtxoOutPoint,
    additional_input: Option<TxInput>,
) -> SignedTransaction {
    let filled_amount = calculate_fill_order(tf, &order_id, fill_amount, OrdersVersion::V1);
    make_fill_order_tx_impl(
        tf,
        order_id,
        token_id,
        fill_amount,
        filled_amount,
        coins_outpoint,
        additional_input,
    )
}

#[allow(clippy::too_many_arguments)]
fn make_fill_order_tx_from_initial_amounts(
    tf: &mut TestFramework,
    order_id: OrderId,
    token_id: TokenId,
    initially_asked: Amount,
    initially_given: Amount,
    fill_amount: Amount,
    coins_outpoint: UtxoOutPoint,
    additional_input: Option<TxInput>,
) -> SignedTransaction {
    let filled_amount =
        orders_accounting::calculate_filled_amount(initially_asked, initially_given, fill_amount)
            .unwrap();
    make_fill_order_tx_impl(
        tf,
        order_id,
        token_id,
        fill_amount,
        filled_amount,
        coins_outpoint,
        additional_input,
    )
}

fn make_fill_order_tx_impl(
    tf: &mut TestFramework,
    order_id: OrderId,
    token_id: TokenId,
    fill_amount: Amount,
    filled_amount: Amount,
    coins_outpoint: UtxoOutPoint,
    additional_input: Option<TxInput>,
) -> SignedTransaction {
    let fill_order_input =
        TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount));
    let coins_amount = tf.coin_amount_from_utxo(&coins_outpoint);
    let fee = TEST_MIN_TX_RELAY_FEE_RATE.atoms_per_kb(); // the tx is expected to be less than 1 kb
    let change = ((coins_amount - fill_amount).unwrap() - Amount::from_atoms(fee)).unwrap();

    let mut tx_builder = TransactionBuilder::new()
        .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
        .add_input(fill_order_input, InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, filled_amount),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(change),
            Destination::AnyoneCanSpend,
        ));
    if let Some(additional_input) = additional_input {
        tx_builder = tx_builder.add_input(additional_input, InputWitness::NoSignature(None));
    }

    tx_builder.build()
}

fn make_freeze_order_tx(
    tf: &mut TestFramework,
    order_id: OrderId,
    coins_outpoint: UtxoOutPoint,
    additional_input: Option<TxInput>,
) -> SignedTransaction {
    let freeze_order_input =
        TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id));
    let coins_amount = tf.coin_amount_from_utxo(&coins_outpoint);
    let fee = TEST_MIN_TX_RELAY_FEE_RATE.atoms_per_kb(); // the tx is expected to be less than 1 kb
    let change = (coins_amount - Amount::from_atoms(fee)).unwrap();

    let mut tx_builder = TransactionBuilder::new()
        .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
        .add_input(freeze_order_input, InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(change),
            Destination::AnyoneCanSpend,
        ));
    if let Some(additional_input) = additional_input {
        tx_builder = tx_builder.add_input(additional_input, InputWitness::NoSignature(None));
    }

    tx_builder.build()
}

fn make_conclude_order_tx(
    tf: &mut TestFramework,
    order_id: OrderId,
    coins_outpoint: UtxoOutPoint,
    additional_input: Option<TxInput>,
) -> SignedTransaction {
    let conclude_order_input =
        TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id));
    let coins_amount = tf.coin_amount_from_utxo(&coins_outpoint);
    let fee = TEST_MIN_TX_RELAY_FEE_RATE.atoms_per_kb(); // the tx is expected to be less than 1 kb
    let change = (coins_amount - Amount::from_atoms(fee)).unwrap();

    let mut tx_builder = TransactionBuilder::new()
        .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
        .add_input(conclude_order_input, InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(change),
            Destination::AnyoneCanSpend,
        ));
    if let Some(additional_input) = additional_input {
        tx_builder = tx_builder.add_input(additional_input, InputWitness::NoSignature(None));
    }

    tx_builder.build()
}

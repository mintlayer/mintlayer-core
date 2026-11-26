// Copyright (c) 2026 RBB S.r.l
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

use rstest::rstest;

use super::{
    helpers::in_memory_storage_wrapper::InMemoryStorageWrapper,
    orders_tests::create_test_framework_with_orders,
};
use chainstate_test_framework::{
    TestFramework, TransactionBuilder,
    helpers::{calculate_fill_order, issue_and_mint_random_token_from_best_block},
};
use chainstate_types::{BlockIndex, BlockStatus};
use common::{
    Uint256,
    chain::{
        AccountCommand, AccountNonce, Currency, Destination, OrderAccountCommand, OrderData,
        OrderId, OrdersVersion, SignedTransaction, TxInput, TxOutput, UtxoOutPoint, make_order_id,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{IsTokenFreezable, TokenId, TokenTotalSupply},
    },
    primitives::{Amount, Idable, id::WithId},
};
use randomness::RngExt as _;
use test_utils::random::{Seed, make_seedable_rng};
use tx_verifier::transaction_verifier::{TransactionSourceForConnect, TransactionVerifier};

/// Create an order giving `give_amount` of the token for `ask_amount` of coins, and a
/// transaction filling it with `fill_amount` of coins. The order is created in a processed
/// block; the fill transaction is returned unprocessed, together with the order id and the
/// amount of tokens paid out for the fill.
fn create_order_and_fill_tx(
    rng: &mut impl randomness::CryptoRng,
    tf: &mut TestFramework,
    version: OrdersVersion,
    token: (TokenId, UtxoOutPoint, UtxoOutPoint),
    ask_amount: Amount,
    give_amount: Amount,
    fill_amount: Amount,
) -> (SignedTransaction, OrderId, Amount) {
    let (token_id, tokens_outpoint, coins_outpoint) = token;
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
    tf.make_block_builder().add_transaction(tx).build_and_process(rng).unwrap();

    let fill_order_input = match version {
        OrdersVersion::V0 => TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::FillOrder(order_id, fill_amount, Destination::AnyoneCanSpend),
        ),
        OrdersVersion::V1 => {
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount))
        }
    };
    let filled_amount = calculate_fill_order(tf, &order_id, fill_amount, version);
    let left_to_fill = (ask_amount - fill_amount).unwrap();
    let tx = TransactionBuilder::new()
        .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
        .add_input(fill_order_input, InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(left_to_fill),
            Destination::AnyoneCanSpend,
        ))
        .add_token_transfer_output_if_non_zero(token_id, filled_amount, Destination::AnyoneCanSpend)
        .build();
    (tx, order_id, filled_amount)
}

/// Issue a token from the genesis outputs and mint some of it; see
/// [`issue_and_mint_random_token_from_best_block`].
fn issue_and_mint_token(
    rng: &mut impl randomness::CryptoRng,
    tf: &mut TestFramework,
) -> (TokenId, UtxoOutPoint, UtxoOutPoint) {
    let genesis_id = tf.genesis().get_id();
    let amount_to_mint = Amount::from_atoms(rng.random_range(1_000..1_000_000_000u128));
    issue_and_mint_random_token_from_best_block(
        rng,
        tf,
        UtxoOutPoint::new(genesis_id.into(), 0),
        amount_to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    )
}

/// The block index of `block` as if it extended the current tip.
fn block_index_of_unprocessed_block(
    tf: &TestFramework,
    block: &WithId<common::chain::Block>,
) -> BlockIndex {
    let prev_block_index = tf.best_block_index();
    BlockIndex::new(
        block,
        Uint256::ZERO,
        prev_block_index.block_id(),
        prev_block_index.block_height().next_height(),
        block.timestamp(),
        0,
        BlockStatus::new(),
    )
}

// Connecting a fill-order transaction to a block records the trade with the amounts of the fill;
// connecting it for the mempool records nothing.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn verifier_records_trade_matches_of_block_fills(
    #[case] seed: Seed,
    #[case] version: OrdersVersion,
) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = create_test_framework_with_orders(&mut rng, version);

        let (token_id, tokens_outpoint, coins_outpoint) = issue_and_mint_token(&mut rng, &mut tf);

        let ask_amount = Amount::from_atoms(rng.random_range(10..1000));
        let give_amount = Amount::from_atoms(rng.random_range(10..1000));
        let fill_amount = Amount::from_atoms(rng.random_range(1..ask_amount.into_atoms()));
        let (fill_tx, order_id, filled_amount) = create_order_and_fill_tx(
            &mut rng,
            &mut tf,
            version,
            (token_id, tokens_outpoint, coins_outpoint),
            ask_amount,
            give_amount,
            fill_amount,
        );

        let storage =
            InMemoryStorageWrapper::new(tf.storage.clone(), tf.chain_config().as_ref().clone());
        let chain_config = tf.chainstate.get_chain_config().clone();

        let block =
            WithId::new(tf.make_block_builder().add_transaction(fill_tx.clone()).build(&mut rng));
        let block_index = block_index_of_unprocessed_block(&tf, &block);
        let median_time_past = tf.genesis().timestamp();

        let mut verifier = TransactionVerifier::new(&storage, chain_config.clone());
        verifier
            .connect_transaction(
                &TransactionSourceForConnect::for_chain(&block_index),
                &fill_tx,
                &median_time_past,
            )
            .unwrap();

        let matches = verifier.take_dex_trade_matches();
        assert_eq!(matches.len(), 1);
        let trade = &matches[0];
        assert_eq!(trade.tx_id, fill_tx.transaction().get_id());
        assert_eq!(trade.input_ordinal, 1);
        assert_eq!(trade.match_ordinal, 0);
        assert_eq!(trade.maker_order_id, order_id);
        assert_eq!(trade.base, Currency::Token(token_id));
        assert_eq!(trade.quote, Currency::Coin);
        assert_eq!(trade.quote_amount, fill_amount);
        assert_eq!(
            trade.base_amount,
            calculate_fill_order(&tf, &order_id, fill_amount, version)
        );
        assert_eq!(trade.base_amount, filled_amount);
        // taking the matches drains them
        assert!(verifier.take_dex_trade_matches().is_empty());

        let mut mempool_verifier = TransactionVerifier::new(&storage, chain_config);
        mempool_verifier
            .connect_transaction(
                &TransactionSourceForConnect::for_mempool(&tf.best_block_index()),
                &fill_tx,
                &median_time_past,
            )
            .unwrap();
        assert!(mempool_verifier.take_dex_trade_matches().is_empty());
    });
}

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

//! Tests of the DEX trade records collected at block connection and announced with the new tip.

use std::time::Duration;

use rstest::rstest;

use super::{
    helpers::in_memory_storage_wrapper::InMemoryStorageWrapper,
    orders_tests::create_test_framework_with_orders,
};
use chainstate::{ChainstateEvent, chainstate_interface::ChainstateInterface as _};
use chainstate_test_framework::{
    TestFramework, TransactionBuilder,
    helpers::{calculate_fill_order, issue_and_mint_random_token_from_best_block, split_utxo},
};
use chainstate_types::{BlockIndex, BlockStatus, DexTradeInfo, DexTradeMatch};
use common::{
    Uint256,
    chain::{
        AccountCommand, AccountNonce, Block, Currency, Destination, GenBlock, OrderAccountCommand,
        OrderData, OrderId, OrdersVersion, SignedTransaction, TxInput, TxOutput, UtxoOutPoint,
        make_order_id,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{IsTokenFreezable, TokenId, TokenTotalSupply},
    },
    primitives::{Amount, BlockHeight, Id, Idable, id::WithId},
};
use randomness::RngExt as _;
use test_utils::random::{Seed, make_seedable_rng};
use tx_verifier::transaction_verifier::{TransactionSourceForConnect, TransactionVerifier};
use utils_networking::broadcaster;

/// How long to wait for an expected trade; the trades are announced synchronously when the
/// block is processed, so this only guards against a lost event.
const TRADE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait to make sure no trade is announced.
const NO_TRADE_TIMEOUT: Duration = Duration::from_millis(100);

/// A coin outpoint together with the amount of coins it holds, so that transactions chaining
/// within a block or across branches can be built before the outpoint exists in the chain.
#[derive(Clone, Debug)]
pub(super) struct CoinUtxo {
    pub(super) outpoint: UtxoOutPoint,
    pub(super) amount: Amount,
}

impl CoinUtxo {
    fn lookup(tf: &TestFramework, outpoint: UtxoOutPoint) -> Self {
        let amount = tf.coin_amount_from_utxo(&outpoint);
        Self { outpoint, amount }
    }
}

/// A transaction with fill-order inputs; see [`make_fill_tx`].
pub(super) struct FillTx {
    pub(super) tx: SignedTransaction,
    /// The amount of tokens paid out for each fill.
    pub(super) payouts: Vec<Amount>,
    /// The position of the fill input in the transaction inputs.
    pub(super) input_ordinal: usize,
    /// The output with the coins left after the fills.
    pub(super) coins_left: CoinUtxo,
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

/// Create one order per token outpoint (in a processed block), each giving `give_amount` of
/// `token_id` for `ask_amount` of coins. Returns the order ids, in the order of the outpoints.
fn create_orders(
    rng: &mut impl randomness::CryptoRng,
    tf: &mut TestFramework,
    token_id: TokenId,
    tokens_outpoints: &[UtxoOutPoint],
    ask_amount: Amount,
    give_amount: Amount,
) -> Vec<OrderId> {
    let mut block_builder = tf.make_block_builder();
    let mut order_ids = Vec::with_capacity(tokens_outpoints.len());
    for tokens_outpoint in tokens_outpoints {
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(ask_amount),
            OutputValue::TokenV1(token_id, give_amount),
        );
        let tx = TransactionBuilder::new()
            .add_input(
                tokens_outpoint.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();
        order_ids.push(make_order_id(tx.inputs()).unwrap());
        block_builder = block_builder.add_transaction(tx);
    }
    block_builder.build_and_process(rng).unwrap();
    order_ids
}

/// Split `tokens_outpoint` into `count` outpoints (in a processed block).
fn split_tokens(
    rng: &mut impl randomness::CryptoRng,
    tf: &mut TestFramework,
    tokens_outpoint: UtxoOutPoint,
    count: usize,
) -> Vec<UtxoOutPoint> {
    let split_tx_id = split_utxo(rng, tf, tokens_outpoint, count);
    (0..count).map(|i| UtxoOutPoint::new(split_tx_id.into(), i as u32)).collect()
}

/// The input filling `fill` coins of `order_id`; `nonce` is the nonce of the order account for
/// orders v0.
fn fill_order_input(
    version: OrdersVersion,
    order_id: OrderId,
    fill: Amount,
    nonce: AccountNonce,
) -> TxInput {
    match version {
        OrdersVersion::V0 => TxInput::AccountCommand(
            nonce,
            AccountCommand::FillOrder(order_id, fill, Destination::AnyoneCanSpend),
        ),
        OrdersVersion::V1 => {
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill))
        }
    }
}

/// A transaction paying with `coin` and filling the given order once (a transaction accepts a
/// single account command), with the paid out tokens and half of the remaining coins as outputs
/// (the rest is the fee). The fill input is the first input of the transaction if
/// `fill_input_first` is set, and the second one otherwise.
/// The payout is computed from the current state, so the order must not have been filled.
pub(super) fn make_fill_tx(
    tf: &TestFramework,
    version: OrdersVersion,
    coin: &CoinUtxo,
    token_id: TokenId,
    order_id: OrderId,
    fill: Amount,
    fill_input_first: bool,
) -> FillTx {
    let coin_input = (
        coin.outpoint.clone().into(),
        InputWitness::NoSignature(None),
    );
    // the orders were never filled, so the nonce of the order account is zero
    let fill_input = (
        fill_order_input(version, order_id, fill, AccountNonce::new(0)),
        InputWitness::NoSignature(None),
    );
    let inputs = if fill_input_first {
        [fill_input, coin_input]
    } else {
        [coin_input, fill_input]
    };
    let mut tx_builder = TransactionBuilder::new();
    for (input, witness) in inputs {
        tx_builder = tx_builder.add_input(input, witness);
    }
    let payout = calculate_fill_order(tf, &order_id, fill, version);
    tx_builder = tx_builder.add_token_transfer_output_if_non_zero(
        token_id,
        payout,
        Destination::AnyoneCanSpend,
    );
    let coins_left_amount = Amount::from_atoms((coin.amount.into_atoms() - fill.into_atoms()) / 2);
    let tx = tx_builder
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_left_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let coins_left = CoinUtxo {
        outpoint: UtxoOutPoint::new(tx.transaction().get_id().into(), 1),
        amount: coins_left_amount,
    };
    FillTx {
        tx,
        payouts: vec![payout],
        input_ordinal: if fill_input_first { 0 } else { 1 },
        coins_left,
    }
}

/// The expected trade of the fill of `fill_tx`, placed at `tx_index` of the block `block_id`
/// at `block_height`.
fn expected_trade(
    block_id: Id<Block>,
    block_height: BlockHeight,
    tx_index: usize,
    fill_tx: &FillTx,
    token_id: TokenId,
    order_id: OrderId,
    fill: Amount,
) -> DexTradeInfo {
    DexTradeInfo::new(
        block_id,
        block_height,
        tx_index,
        DexTradeMatch {
            tx_id: fill_tx.tx.transaction().get_id(),
            input_ordinal: fill_tx.input_ordinal,
            match_ordinal: 0,
            maker_order_id: order_id,
            base: Currency::Token(token_id),
            quote: Currency::Coin,
            base_amount: fill_tx.payouts[0],
            quote_amount: fill,
        },
    )
    .unwrap()
}

/// Receive exactly `count` trades, then make sure no other trade is announced.
async fn expect_trades(
    trades_rx: &mut broadcaster::Receiver<DexTradeInfo>,
    count: usize,
) -> Vec<DexTradeInfo> {
    let mut trades = Vec::with_capacity(count);
    for _ in 0..count {
        let trade = tokio::time::timeout(TRADE_TIMEOUT, trades_rx.recv())
            .await
            .expect("timed out waiting for a trade")
            .expect("trades channel closed");
        trades.push(trade);
    }
    if let Ok(unexpected) = tokio::time::timeout(NO_TRADE_TIMEOUT, trades_rx.recv()).await {
        panic!("unexpected extra trade: {unexpected:?}");
    }
    trades
}

/// Receive the next new tip event and check that it announces the given block.
async fn expect_new_tip(
    tips_rx: &mut broadcaster::Receiver<ChainstateEvent>,
    tf: &TestFramework,
    block_id: Id<Block>,
) {
    let tip = tokio::time::timeout(TRADE_TIMEOUT, tips_rx.recv())
        .await
        .expect("timed out waiting for a new tip")
        .expect("tips channel closed");
    match tip {
        ChainstateEvent::NewTip { id, height, .. } => {
            assert_eq!(id, Id::<GenBlock>::from(block_id));
            assert_eq!(height, tf.block_index(&block_id).block_height());
        }
    }
}

/// Build a block with the given transactions on top of `parent`, without processing it.
fn build_block(
    tf: &mut TestFramework,
    rng: &mut impl randomness::CryptoRng,
    parent: Id<GenBlock>,
    txs: impl IntoIterator<Item = SignedTransaction>,
) -> WithId<Block> {
    let builder = txs.into_iter().fold(tf.make_block_builder(), |builder, tx| {
        builder.add_transaction(tx)
    });
    WithId::new(builder.with_parent(parent).build(rng))
}

/// Build and process a block with the given transactions on top of `parent`; return its id.
pub(super) fn process_block_with_txs(
    tf: &mut TestFramework,
    rng: &mut impl randomness::CryptoRng,
    parent: Id<GenBlock>,
    txs: impl IntoIterator<Item = SignedTransaction>,
) -> Id<Block> {
    let block = build_block(tf, rng, parent, txs);
    let block_id = block.get_id();
    tf.process_block(WithId::take(block), chainstate::BlockSource::Local).unwrap();
    block_id
}

/// Build and process an empty block on top of the best block; return its id.
fn process_empty_block(tf: &mut TestFramework, rng: &mut impl randomness::CryptoRng) -> Id<Block> {
    let parent = tf.best_block_id();
    process_block_with_txs(tf, rng, parent, [])
}

/// The block index of `block` as if it extended the current tip.
fn block_index_of_unprocessed_block(tf: &TestFramework, block: &WithId<Block>) -> BlockIndex {
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

/// The fixture of the tests: a token, `orders_count` orders giving tokens for coins (created
/// in one block), and the coin outpoint to pay for the fills.
pub(super) struct Fixture {
    pub(super) token_id: TokenId,
    pub(super) coin: CoinUtxo,
    pub(super) order_ids: Vec<OrderId>,
}

pub(super) fn create_fixture(
    rng: &mut impl randomness::CryptoRng,
    tf: &mut TestFramework,
    orders_count: usize,
) -> Fixture {
    let (token_id, tokens_outpoint, coins_outpoint) = issue_and_mint_token(rng, tf);
    let coin = CoinUtxo::lookup(tf, coins_outpoint);
    let tokens_outpoints = split_tokens(rng, tf, tokens_outpoint, orders_count);
    let order_ids = create_orders(
        rng,
        tf,
        token_id,
        &tokens_outpoints,
        Amount::from_atoms(500),
        Amount::from_atoms(1000),
    );
    Fixture {
        token_id,
        coin,
        order_ids,
    }
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
        let fixture = create_fixture(&mut rng, &mut tf, 1);

        let fill_amount = Amount::from_atoms(rng.random_range(1..500));
        let fill = make_fill_tx(
            &tf,
            version,
            &fixture.coin,
            fixture.token_id,
            fixture.order_ids[0],
            fill_amount,
            false,
        );

        let storage =
            InMemoryStorageWrapper::new(tf.storage.clone(), tf.chain_config().as_ref().clone());
        let chain_config = tf.chainstate.get_chain_config().clone();

        let parent = tf.best_block_id();
        let block = build_block(&mut tf, &mut rng, parent, [fill.tx.clone()]);
        let block_index = block_index_of_unprocessed_block(&tf, &block);
        let median_time_past = tf.genesis().timestamp();

        let mut verifier = TransactionVerifier::new(&storage, chain_config.clone());
        verifier
            .connect_transaction(
                &TransactionSourceForConnect::for_chain(&block_index),
                &fill.tx,
                &median_time_past,
            )
            .unwrap();

        let matches = verifier.take_dex_trade_matches();
        assert_eq!(matches.len(), 1);
        let trade = &matches[0];
        assert_eq!(trade.tx_id, fill.tx.transaction().get_id());
        assert_eq!(trade.input_ordinal, 1);
        assert_eq!(trade.match_ordinal, 0);
        assert_eq!(trade.maker_order_id, fixture.order_ids[0]);
        assert_eq!(trade.base, Currency::Token(fixture.token_id));
        assert_eq!(trade.quote, Currency::Coin);
        assert_eq!(trade.quote_amount, fill_amount);
        assert_eq!(
            trade.base_amount,
            calculate_fill_order(&tf, &fixture.order_ids[0], fill_amount, version)
        );
        assert_eq!(trade.base_amount, fill.payouts[0]);
        // taking the matches drains them
        assert!(verifier.take_dex_trade_matches().is_empty());

        let mut mempool_verifier = TransactionVerifier::new(&storage, chain_config);
        mempool_verifier
            .connect_transaction(
                &TransactionSourceForConnect::for_mempool(&tf.best_block_index()),
                &fill.tx,
                &median_time_past,
            )
            .unwrap();
        assert!(mempool_verifier.take_dex_trade_matches().is_empty());
    });
}

// Processing a block with a fill announces its trade together with the new tip; an empty block
// announces only the new tip.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
#[tokio::test]
async fn fill_block_announces_trade_with_new_tip(
    #[case] seed: Seed,
    #[case] version: OrdersVersion,
) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = create_test_framework_with_orders(&mut rng, version);
    let fixture = create_fixture(&mut rng, &mut tf, 1);

    let mut trades_rx = tf.chainstate.subscribe_to_rpc_dex_trades();
    let mut tips_rx = tf.chainstate.subscribe_to_rpc_events();

    let fill_amount = Amount::from_atoms(rng.random_range(1..500));
    let fill = make_fill_tx(
        &tf,
        version,
        &fixture.coin,
        fixture.token_id,
        fixture.order_ids[0],
        fill_amount,
        false,
    );
    let parent = tf.best_block_id();
    let block_id = process_block_with_txs(&mut tf, &mut rng, parent, [fill.tx.clone()]);

    let trades = expect_trades(&mut trades_rx, 1).await;
    assert_eq!(
        trades[0],
        expected_trade(
            block_id,
            tf.block_index(&block_id).block_height(),
            0,
            &fill,
            fixture.token_id,
            fixture.order_ids[0],
            fill_amount,
        )
    );
    // the fill input is the second input of the only transaction of the block
    assert_eq!(trades[0].in_block_position(), 1 << 8);
    expect_new_tip(&mut tips_rx, &tf, block_id).await;

    let empty_block_id = process_empty_block(&mut tf, &mut rng);
    expect_trades(&mut trades_rx, 0).await;
    expect_new_tip(&mut tips_rx, &tf, empty_block_id).await;
}

// The trades of a block with several fill transactions are announced in the order of their
// position in the block, whatever the position of the fill input within its transaction.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
#[tokio::test]
async fn multiple_fills_announced_in_block_order(
    #[case] seed: Seed,
    #[case] version: OrdersVersion,
) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = create_test_framework_with_orders(&mut rng, version);
    let fixture = create_fixture(&mut rng, &mut tf, 4);

    let mut trades_rx = tf.chainstate.subscribe_to_rpc_dex_trades();

    let fill_amount = Amount::from_atoms(100);
    // each transaction pays with the coins left by the previous one; the fill input alternates
    // between the first and the second position within the transaction
    let mut coin = fixture.coin.clone();
    let mut fill_txs = Vec::new();
    for (tx_index, order_id) in fixture.order_ids.iter().enumerate() {
        let fill_input_first = tx_index % 2 == 0;
        let fill_tx = make_fill_tx(
            &tf,
            version,
            &coin,
            fixture.token_id,
            *order_id,
            fill_amount,
            fill_input_first,
        );
        coin = fill_tx.coins_left.clone();
        fill_txs.push((fill_tx, *order_id));
    }
    let parent = tf.best_block_id();
    let block_id = process_block_with_txs(
        &mut tf,
        &mut rng,
        parent,
        fill_txs.iter().map(|(fill_tx, _)| fill_tx.tx.clone()),
    );
    let block_height = tf.block_index(&block_id).block_height();

    let trades = expect_trades(&mut trades_rx, fill_txs.len()).await;
    let mut expected_positions = Vec::new();
    for (tx_index, ((fill_tx, order_id), trade)) in fill_txs.iter().zip(trades.iter()).enumerate() {
        assert_eq!(
            trade,
            &expected_trade(
                block_id,
                block_height,
                tx_index,
                fill_tx,
                fixture.token_id,
                *order_id,
                fill_amount,
            )
        );
        expected_positions.push(((tx_index as u64) << 40) | (fill_tx.input_ordinal as u64) << 8);
    }
    let positions: Vec<_> = trades.iter().map(DexTradeInfo::in_block_position).collect();
    assert_eq!(positions, expected_positions);
    // the positions are strictly increasing, in (tx index, input ordinal, match ordinal) order
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    // the identity tuples of the trades are distinct
    let identities: std::collections::BTreeSet<_> = trades
        .iter()
        .map(|trade| {
            (
                trade.block_id,
                trade.tx_id,
                trade.input_ordinal,
                trade.match_ordinal,
            )
        })
        .collect();
    assert_eq!(identities.len(), trades.len());
}

// A block connected without becoming the tip announces nothing; when a later block makes the
// node switch to its branch, the trades of the branch are announced in connect order and nothing
// is announced for the blocks that were disconnected.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn side_branch_trades_announced_when_the_branch_is_activated(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let version = OrdersVersion::V1;
    let mut tf = create_test_framework_with_orders(&mut rng, version);
    let fixture = create_fixture(&mut rng, &mut tf, 2);

    let mut trades_rx = tf.chainstate.subscribe_to_rpc_dex_trades();
    let fork_point = tf.best_block_id();
    let fill_amount = Amount::from_atoms(100);

    // the main chain gets an empty block, so that the side branch is one block behind
    process_empty_block(&mut tf, &mut rng);
    expect_trades(&mut trades_rx, 0).await;

    // a side branch with two blocks with fills: stored but not activated
    let side_fill0 = make_fill_tx(
        &tf,
        version,
        &fixture.coin,
        fixture.token_id,
        fixture.order_ids[0],
        fill_amount,
        false,
    );
    let side_block0 = build_block(&mut tf, &mut rng, fork_point, [side_fill0.tx.clone()]);
    let side_block0_id = side_block0.get_id();
    tf.process_block(WithId::take(side_block0), chainstate::BlockSource::Local)
        .unwrap();
    // the first side block has the same trust as the main chain block: it does not become the tip
    expect_trades(&mut trades_rx, 0).await;

    let side_fill1 = make_fill_tx(
        &tf,
        version,
        &side_fill0.coins_left,
        fixture.token_id,
        fixture.order_ids[1],
        fill_amount,
        false,
    );
    let side_block1_id = process_block_with_txs(
        &mut tf,
        &mut rng,
        side_block0_id.into(),
        [side_fill1.tx.clone()],
    );

    // the switch disconnects the main chain block (no trade for it) and connects the side branch
    // in order; the trade of the first side block is announced now, when it is connected
    let trades = expect_trades(&mut trades_rx, 2).await;
    let side_fills = [
        (
            &side_fill0,
            side_block0_id,
            tf.block_index(&side_block0_id).block_height(),
            fixture.order_ids[0],
        ),
        (
            &side_fill1,
            side_block1_id,
            tf.block_index(&side_block1_id).block_height(),
            fixture.order_ids[1],
        ),
    ];
    for (index, trade) in trades.iter().enumerate() {
        let (fill_tx, block_id, block_height, order_id) = &side_fills[index];
        assert_eq!(
            trade,
            &expected_trade(
                *block_id,
                *block_height,
                0,
                fill_tx,
                fixture.token_id,
                *order_id,
                fill_amount,
            )
        );
    }
    // the position is relative to the block: the trades are ordered by the height of their block
    assert!(trades[0].block_height < trades[1].block_height);
    assert_eq!(tf.best_block_id(), Id::<GenBlock>::from(side_block1_id));
}

// Invalidating a main chain block with trades announces nothing for the disconnected blocks and
// the trades of the branch that is activated instead; resetting the failure flags announces the
// trades of the restored branch when it is activated again.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn invalidation_announces_trades_of_the_activated_branch(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let version = OrdersVersion::V1;
    let mut tf = create_test_framework_with_orders(&mut rng, version);
    let fixture = create_fixture(&mut rng, &mut tf, 3);

    let mut trades_rx = tf.chainstate.subscribe_to_rpc_dex_trades();
    let mut tips_rx = tf.chainstate.subscribe_to_rpc_events();
    let fill_amount = Amount::from_atoms(100);

    // the main chain: two blocks with fills; the side branch: one block with a fill
    let fork_point = tf.best_block_id();
    let main_fill0 = make_fill_tx(
        &tf,
        version,
        &fixture.coin,
        fixture.token_id,
        fixture.order_ids[0],
        fill_amount,
        false,
    );
    let main_block0_id =
        process_block_with_txs(&mut tf, &mut rng, fork_point, [main_fill0.tx.clone()]);
    let main_fill1 = make_fill_tx(
        &tf,
        version,
        &main_fill0.coins_left,
        fixture.token_id,
        fixture.order_ids[1],
        fill_amount,
        false,
    );
    let main_block1_id = process_block_with_txs(
        &mut tf,
        &mut rng,
        main_block0_id.into(),
        [main_fill1.tx.clone()],
    );
    let main_blocks = [
        (
            &main_fill0,
            main_block0_id,
            tf.block_index(&main_block0_id).block_height(),
            fixture.order_ids[0],
        ),
        (
            &main_fill1,
            main_block1_id,
            tf.block_index(&main_block1_id).block_height(),
            fixture.order_ids[1],
        ),
    ];
    let assert_main_trades = |trades: &[DexTradeInfo]| {
        for (index, trade) in trades.iter().enumerate() {
            let (fill_tx, block_id, block_height, order_id) = main_blocks[index];
            assert_eq!(
                trade,
                &expected_trade(
                    block_id,
                    block_height,
                    0,
                    fill_tx,
                    fixture.token_id,
                    order_id,
                    fill_amount,
                )
            );
        }
    };
    let trades = expect_trades(&mut trades_rx, 2).await;
    assert_main_trades(&trades);
    expect_new_tip(&mut tips_rx, &tf, main_block0_id).await;
    expect_new_tip(&mut tips_rx, &tf, main_block1_id).await;

    let side_fill = make_fill_tx(
        &tf,
        version,
        &fixture.coin,
        fixture.token_id,
        fixture.order_ids[2],
        fill_amount,
        false,
    );
    let side_block = build_block(&mut tf, &mut rng, fork_point, [side_fill.tx.clone()]);
    let side_block_id = side_block.get_id();
    tf.process_block(WithId::take(side_block), chainstate::BlockSource::Local)
        .unwrap();
    let side_block_height = tf.block_index(&side_block_id).block_height();
    // the side block is stored but not activated
    expect_trades(&mut trades_rx, 0).await;

    // invalidating the first main chain block disconnects both main chain blocks and activates
    // the side branch: only the trade of the side block is announced, with the new tip
    tf.chainstate.invalidate_block(&main_block0_id).unwrap();
    let trades = expect_trades(&mut trades_rx, 1).await;
    assert_eq!(
        trades[0],
        expected_trade(
            side_block_id,
            side_block_height,
            0,
            &side_fill,
            fixture.token_id,
            fixture.order_ids[2],
            fill_amount,
        )
    );
    expect_new_tip(&mut tips_rx, &tf, side_block_id).await;
    assert_eq!(tf.best_block_id(), Id::<GenBlock>::from(side_block_id));

    // resetting the failure flags restores the longer main chain, whose trades are announced
    // again when it is connected; nothing is announced for the side block being disconnected
    tf.chainstate.reset_block_failure_flags(&main_block0_id).unwrap();
    let trades = expect_trades(&mut trades_rx, 2).await;
    assert_main_trades(&trades);
    expect_new_tip(&mut tips_rx, &tf, main_block1_id).await;
    assert_eq!(tf.best_block_id(), Id::<GenBlock>::from(main_block1_id));
}

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

//! End-to-end test of the `dex_subscribe_to_trades` subscription over websockets.

use std::{net::SocketAddr, time::Duration};

use rstest::rstest;

use super::{
    dex_trades_tests::{create_fixture, make_fill_tx, process_block_with_txs},
    orders_tests::create_test_framework_with_orders,
};
use chainstate::{
    BlockSource, ChainstateConfig, DefaultTransactionVerificationStrategy,
    MAX_DEX_TRADES_SUBSCRIBERS,
    chainstate_interface::ChainstateInterface,
    rpc::{ChainstateRpcClient as _, ChainstateRpcServer as _, RpcDexTradeEvent, RpcTradingPair},
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{Block, OrdersVersion},
    primitives::{Amount, Idable},
};
use test_utils::random::{Seed, make_seedable_rng};

/// How long to wait for an expected event.
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for an event that is not expected to come.
const NO_EVENT_TIMEOUT: Duration = Duration::from_millis(200);
const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Receive the next trade of a subscription, failing if it does not come in time.
macro_rules! next_trade {
    ($subscription:expr) => {
        tokio::time::timeout(EVENT_TIMEOUT, $subscription.next())
            .await
            .expect("timed out waiting for the trade")
            .unwrap()
            .unwrap()
    };
}

/// A fresh chainstate with the chain configuration of `tf`, served over websockets.
struct RunningRpc {
    chainstate: subsystem::Handle<dyn ChainstateInterface>,
    server: rpc::Rpc,
    shutdown: subsystem::ShutdownTrigger,
    manager: subsystem::ManagerJoinHandle,
}

impl RunningRpc {
    async fn start(tf: &TestFramework) -> Self {
        let storage = chainstate_storage::inmemory::Store::new_empty().unwrap();
        let mut man = subsystem::Manager::new("dex-trades-rpc");
        let shutdown = man.make_shutdown_trigger();
        let chainstate = man.add_subsystem(
            "chainstate",
            chainstate::make_chainstate(
                tf.chain_config().clone(),
                ChainstateConfig::new(),
                storage,
                DefaultTransactionVerificationStrategy::new(),
                None,
                // the clock of the framework, so that the blocks of the test chain are fresh and
                // the chainstate leaves the initial block download like the framework's one
                tf.time_getter.clone(),
                None,
            )
            .unwrap(),
        );
        let manager = man.main_in_task();

        let server = rpc::Builder::new("127.0.0.1:0".parse::<SocketAddr>().unwrap(), None)
            .register(chainstate.clone().into_rpc())
            .build()
            .await
            .unwrap();
        Self {
            chainstate,
            server,
            shutdown,
            manager,
        }
    }

    /// A new client connected to the same server.
    async fn connect(&self) -> rpc::RpcWsClient {
        rpc::new_ws_client(
            format!("ws://{}", self.server.http_address()),
            rpc::RpcAuthData::None,
        )
        .await
        .unwrap()
    }

    async fn stop(self) {
        self.shutdown.initiate();
        self.manager.join().await;
        subsystem::Subsystem::shutdown(self.server).await;
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn rpc_subscription_delivers_filtered_trades(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let version = OrdersVersion::V1;
    let mut tf = create_test_framework_with_orders(&mut rng, version);
    let fixture = create_fixture(&mut rng, &mut tf, 1);

    // the blocks of the test chain, ending with a block containing a fill
    let fill_amount = Amount::from_atoms(100);
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
    let fill_block_id = process_block_with_txs(&mut tf, &mut rng, parent, [fill.tx.clone()]);
    let blocks: Vec<Block> = (1..=tf.best_block_height().into_int())
        .map(|height| tf.block(tf.to_chain_block_id(&tf.block_id(height))))
        .collect();

    let rpc = RunningRpc::start(&tf).await;
    let client = rpc.connect().await;

    // the trade of the fill gives tokens for coins: the pair of the maker is (token, coin)
    let pair_of_the_trade = RpcTradingPair {
        base: format!("{:x}", fixture.token_id),
        quote: "coin".to_owned(),
    };
    let reversed_pair = RpcTradingPair {
        base: "coin".to_owned(),
        quote: format!("{:x}", fixture.token_id),
    };
    let mut all_trades = client.dex_subscribe_to_trades(None).await.unwrap();
    let mut pair_trades =
        client.dex_subscribe_to_trades(Some(vec![pair_of_the_trade])).await.unwrap();
    let mut reversed_pair_trades =
        client.dex_subscribe_to_trades(Some(vec![reversed_pair])).await.unwrap();
    let mut empty_filter_trades = client.dex_subscribe_to_trades(Some(vec![])).await.unwrap();

    // a malformed pair rejects the subscription with an error naming the offender
    let malformed = RpcTradingPair {
        base: "not-a-token-id".to_owned(),
        quote: "coin".to_owned(),
    };
    let error = match client.dex_subscribe_to_trades(Some(vec![malformed])).await {
        Err(error) => error,
        Ok(_) => panic!("a malformed pair must reject the subscription"),
    };
    assert!(
        error.to_string().contains("not-a-token-id"),
        "unexpected error: {error}"
    );

    // replaying the blocks into the served chainstate announces the trade to the subscribers
    // whose filter matches it, as identical JSON
    for block in blocks {
        rpc.chainstate
            .call_mut(move |this| this.process_block(block, BlockSource::Local))
            .await
            .unwrap()
            .unwrap();
    }

    let all_event = next_trade!(all_trades);
    let all_json = serde_json::to_value(&all_event).unwrap();
    assert_eq!(
        all_json,
        serde_json::to_value(next_trade!(pair_trades)).unwrap()
    );
    // an empty list of pairs delivers everything, like an absent one
    assert_eq!(
        all_json,
        serde_json::to_value(next_trade!(empty_filter_trades)).unwrap()
    );
    let RpcDexTradeEvent::DexTrade {
        tx_id,
        block_id,
        base_token_id,
        quote_token_id,
        base_amount,
        quote_amount,
        in_block_position,
        ..
    } = all_event;
    assert_eq!(tx_id, fill.tx.transaction().get_id());
    assert_eq!(block_id, fill_block_id);
    assert_eq!(base_token_id, format!("{:x}", fixture.token_id));
    assert_eq!(quote_token_id, "coin");
    assert_eq!(base_amount, fill.payouts[0].into_atoms().to_string());
    assert_eq!(quote_amount, "100");
    assert_eq!(in_block_position, 1 << 4);

    // the reversed pair delivers nothing, and no other trade was announced
    assert!(
        tokio::time::timeout(NO_EVENT_TIMEOUT, reversed_pair_trades.next())
            .await
            .is_err()
    );
    assert!(tokio::time::timeout(NO_EVENT_TIMEOUT, all_trades.next()).await.is_err());

    drop(client);
    rpc.stop().await;
}

// The subscriber cap counts live subscriptions only: clients that go away free their slots even
// if no trade would ever have tried their (never matching) pair filter.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn disconnected_subscribers_free_their_slots(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let version = OrdersVersion::V1;
    let mut tf = create_test_framework_with_orders(&mut rng, version);
    let fixture = create_fixture(&mut rng, &mut tf, 1);
    let rpc = RunningRpc::start(&tf).await;

    // one connection fills the cap with subscriptions for a market without trades
    let never_trading = RpcTradingPair {
        base: format!("{:x}", fixture.token_id),
        quote: "coin".to_owned(),
    };
    let client = rpc.connect().await;
    let mut subscriptions = Vec::new();
    for _ in 0..MAX_DEX_TRADES_SUBSCRIBERS {
        subscriptions
            .push(client.dex_subscribe_to_trades(Some(vec![never_trading.clone()])).await.unwrap());
    }
    let error = match client.dex_subscribe_to_trades(None).await {
        Err(error) => error,
        Ok(_) => panic!("the subscriber cap must be reached"),
    };
    assert!(
        error.to_string().contains("too many DEX trades subscribers"),
        "unexpected error: {error}"
    );

    // the connection goes away: its slots are reclaimed, and another client can subscribe
    drop(subscriptions);
    drop(client);
    let other = rpc.connect().await;
    let mut rejected = 0;
    let subscription = loop {
        match other.dex_subscribe_to_trades(None).await {
            Ok(subscription) => break subscription,
            Err(error) if error.to_string().contains("too many DEX trades subscribers") => {
                rejected += 1;
                assert!(rejected < 200, "the slots were not reclaimed");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("unexpected error: {error}"),
        }
    };
    drop(subscription);

    rpc.stop().await;
}

/// The end of the stream is observable: when the node (and with it the dispatcher queues) goes
/// away, the client's subscription stream ENDS (next() yields None) instead of waiting forever.
/// The final error notification jsonrpsee sends is swallowed by the jsonrpsee Rust client
/// itself (process_subscription_close_response drops the payload); non-jsonrpsee clients see
/// the full notification on the wire.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn the_client_sees_the_subscription_end(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let version = OrdersVersion::V1;
    let mut tf = create_test_framework_with_orders(&mut rng, version);
    let _fixture = create_fixture(&mut rng, &mut tf, 1);
    let rpc = RunningRpc::start(&tf).await;

    let client = rpc.connect().await;
    let mut trades = client.dex_subscribe_to_trades(None).await.unwrap();

    rpc.stop().await;
    let final_item = tokio::time::timeout(NOTIFICATION_TIMEOUT, trades.next())
        .await
        .expect("the subscription termination was not observed by the client");
    assert!(
        final_item.is_none(),
        "the subscription must end with the stream, not with another item: {final_item:?}"
    );
}

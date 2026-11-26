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
    chainstate_interface::ChainstateInterface,
    rpc::{ChainstateRpcClient as _, ChainstateRpcServer as _, RpcDexTradeEvent, RpcTradingPair},
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{Block, OrdersVersion},
    primitives::{Amount, Idable},
};
use test_utils::random::{Seed, make_seedable_rng};

/// How long to wait for an event that is not expected to come.
const NO_EVENT_TIMEOUT: Duration = Duration::from_millis(200);

/// A fresh chainstate with the chain configuration of `tf`, served over websockets.
struct RunningRpc {
    client: rpc::RpcWsClient,
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
                Default::default(),
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
        let client = rpc::new_ws_client(
            format!("ws://{}", server.http_address()),
            rpc::RpcAuthData::None,
        )
        .await
        .unwrap();
        Self {
            client,
            chainstate,
            server,
            shutdown,
            manager,
        }
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

    let RunningRpc {
        client,
        chainstate,
        server,
        shutdown,
        manager,
    } = RunningRpc::start(&tf).await;

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
        chainstate
            .call_mut(move |this| this.process_block(block, BlockSource::Local))
            .await
            .unwrap()
            .unwrap();
    }

    let all_event = all_trades.next().await.unwrap().unwrap();
    let all_json = serde_json::to_value(&all_event).unwrap();
    assert_eq!(
        all_json,
        serde_json::to_value(pair_trades.next().await.unwrap().unwrap()).unwrap()
    );
    // an empty list of pairs delivers everything, like an absent one
    assert_eq!(
        all_json,
        serde_json::to_value(empty_filter_trades.next().await.unwrap().unwrap()).unwrap()
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
    assert_eq!(in_block_position, 1 << 8);

    // the reversed pair delivers nothing, and no other trade was announced
    assert!(
        tokio::time::timeout(NO_EVENT_TIMEOUT, reversed_pair_trades.next())
            .await
            .is_err()
    );
    assert!(tokio::time::timeout(NO_EVENT_TIMEOUT, all_trades.next()).await.is_err());

    RunningRpc {
        client,
        chainstate,
        server,
        shutdown,
        manager,
    }
    .stop()
    .await;
}

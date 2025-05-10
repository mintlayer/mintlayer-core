// Copyright (c) 2023 RBB S.r.l
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

mod utils;

use logging::log;
use rstest::*;

use common::{
    chain::{Block, Transaction, UtxoOutPoint},
    primitives::{Amount, BlockHeight, Id},
};
use utils::{
    make_seedable_rng, ClientT, JsonValue, Seed, Subscription, SubscriptionClientT, ACCOUNT0_ARG,
    ACCOUNT1_ARG,
};
use wallet_rpc_lib::{
    types::{
        AddressInfo, Balances, BlockInfo, NewAccountInfo, NewSubmittedTransaction, RpcAmountIn,
        RpcUtxoState, TransactionOptions,
    },
    TxState,
};

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn startup_shutdown(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;

    let wallet = tf.handle();
    assert!(wallet.is_running());

    let rpc_client = tf.rpc_client_http();
    let genesis_id = tf.chain_config().genesis_block_id();
    let best_block: BlockInfo =
        rpc_client.request("wallet_best_block", Vec::<u32>::new()).await.unwrap();
    assert_eq!(best_block.id, genesis_id);
    assert_eq!(best_block.height, BlockHeight::new(0));

    tf.stop().await;
    assert!(!wallet.is_running());
}

#[derive(Eq, PartialEq, Clone, Debug)]
enum EventInfo {
    TxUpdated { id: Id<Transaction>, state: TxState },
    TxDropped { id: Id<Transaction> },
    RewardAdded {},
}

impl EventInfo {
    fn from_json(evt_json: JsonValue) -> Self {
        log::trace!("Loading event {evt_json:#}");
        let (key, val) = evt_json.as_object().unwrap().iter().next().unwrap();
        let obj = val.as_object().unwrap();

        match key.as_str() {
            "TxUpdated" => {
                let id = serde_json::from_value(obj["tx_id"].clone()).unwrap();
                let state = serde_json::from_value(obj["state"].clone()).unwrap();
                EventInfo::TxUpdated { id, state }
            }
            "TxDropped" => {
                let id = serde_json::from_value(obj["tx_id"].clone()).unwrap();
                EventInfo::TxDropped { id }
            }
            "RewardAdded" => Self::RewardAdded {},
            _ => panic!("Unrecognized event"),
        }
    }

    fn tx_id(&self) -> Id<Transaction> {
        match self {
            EventInfo::TxUpdated { id, state: _ } => *id,
            EventInfo::TxDropped { id } => *id,
            EventInfo::RewardAdded {} => panic!("Not a transaction event"),
        }
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn stake_and_send_coins_to_acct1(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;

    let wallet_rpc = tf.rpc_client_ws().await;

    // Create a new account
    let addr_result: Result<AddressInfo, _> =
        wallet_rpc.request("address_new", [ACCOUNT1_ARG]).await;
    assert!(addr_result.is_err());
    let new_acct: NewAccountInfo =
        wallet_rpc.request("account_create", Vec::<u32>::new()).await.unwrap();
    assert_eq!(new_acct.account, 1);
    let acct1_addr: AddressInfo = wallet_rpc.request("address_new", [ACCOUNT1_ARG]).await.unwrap();
    log::debug!("acct1_addr: {acct1_addr:?}");

    // Start listening to the wallet events
    let mut wallet_events: Subscription<JsonValue> = wallet_rpc
        .subscribe(
            "subscribe_wallet_events",
            Vec::<u32>::new(),
            "unsubscribe_wallet_events",
        )
        .await
        .unwrap();

    let all_utxo_states = enum_iterator::all::<RpcUtxoState>().collect::<Vec<_>>();

    // Get balance info
    let balances: Balances = wallet_rpc
        .request("account_balance", (ACCOUNT0_ARG, &all_utxo_states))
        .await
        .unwrap();
    let coins_before = balances.coins().amount();
    log::debug!("Balances: {balances:?}");

    // Get UTXOs
    let utxos: JsonValue = wallet_rpc.request("account_utxos", [ACCOUNT0_ARG]).await.unwrap();
    log::trace!("UTXOs: {utxos:#}");
    let utxos = utxos.as_array().unwrap();
    assert_eq!(utxos.len(), 2);

    // Extract amount from the genesis UTXO
    let (utxo_amount, _outpoint0) = {
        let utxo0 = utxos[0].as_object().unwrap();
        let outpt = utxo0["outpoint"].as_object().unwrap();
        let id_obj = outpt["source_id"].as_object().unwrap()["content"].as_object().unwrap();
        let id = id_obj["block_id"].as_str().unwrap();
        let index = outpt["index"].as_u64().unwrap();
        assert_eq!(index, 0);

        let output = &utxo0["output"].as_object().unwrap()["content"].as_object().unwrap()["value"]
            .as_object()
            .unwrap();
        let amount_val =
            &output["content"].as_object().unwrap()["amount"].as_object().unwrap()["atoms"];
        let amount = amount_val.as_str().unwrap().parse::<u128>().unwrap();

        let source_id: Id<Block> = wallet_test_node::decode_hex(id);
        let outpt = UtxoOutPoint::new(source_id.into(), index as u32);
        (amount, outpt)
    };

    // Check the balance and UTXO amount matches
    assert_eq!(utxo_amount, coins_before.into_atoms());

    let to_send_amount = Amount::from_atoms(utxo_amount / 2);
    let _: NewSubmittedTransaction = {
        let send_to_addr = acct1_addr.address;
        let options = TransactionOptions {
            in_top_x_mb: Some(3),
            broadcast_to_mempool: Some(true),
        };
        let params = (
            ACCOUNT0_ARG,
            send_to_addr,
            RpcAmountIn::from_atoms(to_send_amount),
            Vec::<UtxoOutPoint>::new(),
            options,
        );
        wallet_rpc.request("address_send", params).await.unwrap()
    };

    let balances: Balances = wallet_rpc
        .request("account_balance", (ACCOUNT0_ARG, &all_utxo_states))
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let evt1 = EventInfo::from_json(wallet_events.next().await.unwrap().unwrap());

    assert!(matches!(
        evt1,
        EventInfo::TxUpdated {
            // Note: The wallet does not currently track mempool.
            state: TxState::Inactive { .. },
            id: _,
        }
    ));

    let coins_after = balances.coins().amount();
    assert!(coins_after <= (coins_before / 2).unwrap());
    assert!(coins_after >= (coins_before / 3).unwrap());

    let balances: Balances = wallet_rpc
        .request("account_balance", (ACCOUNT1_ARG, &all_utxo_states))
        .await
        .unwrap();
    log::debug!("acct1 balances: {balances:?}");

    let _result: JsonValue = wallet_rpc
        .request("node_generate_block", (ACCOUNT0_ARG, [(); 0]))
        .await
        .unwrap();

    // Start staking on account 0 to hopefully create a block that contains our transaction
    let _: () = wallet_rpc.request("staking_start", [ACCOUNT0_ARG]).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let evt3 = EventInfo::from_json(wallet_events.next().await.unwrap().unwrap());
    assert_eq!(evt3, EventInfo::RewardAdded {});

    let evt4 = EventInfo::from_json(wallet_events.next().await.unwrap().unwrap());
    assert!(matches!(
        evt4,
        EventInfo::TxUpdated {
            state: TxState::Confirmed { .. },
            id: _,
        }
    ));
    assert_eq!(evt4.tx_id(), evt1.tx_id());

    std::mem::drop(wallet_rpc);
    tf.stop().await;
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn no_hexified_destination(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;

    let wallet_rpc = tf.rpc_client_http();

    // Get balance info
    let utxos: JsonValue = wallet_rpc.request("account_utxos", [ACCOUNT0_ARG]).await.unwrap();
    log::trace!("UTXOs: {utxos:#}");

    // Should not contain any "Hexified" values as these should have been converted to bech32m.
    let utxos_string = utxos.to_string();
    assert!(!utxos_string.contains("Hexified"));

    tf.stop().await;
}

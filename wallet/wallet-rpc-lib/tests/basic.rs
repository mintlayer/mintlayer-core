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
use rstest::rstest;

use common::{
    chain::{Block, UtxoOutPoint},
    primitives::{Amount, BlockHeight, Id},
};
use utils::{make_seedable_rng, ClientT, JsonValue, Seed, ACCOUNT0_ARG, ACCOUNT1_ARG};
use wallet_rpc_lib::types::{
    AddressInfo, Balances, BlockInfo, EmptyArgs, NewAccountInfo, TransactionOptions,
};

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn startup_shutdown(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;

    let wallet = tf.handle();
    assert!(wallet.is_running());

    let rpc_client = tf.rpc_client();
    let genesis_id = tf.wallet_service.chain_config().genesis_block_id();
    let best_block: BlockInfo = rpc_client.request("best_block", [EmptyArgs {}]).await.unwrap();
    assert_eq!(best_block.id, genesis_id);
    assert_eq!(best_block.height, BlockHeight::new(0));

    tf.stop().await;
    assert!(!wallet.is_running());
}

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn send_coins_to_acct1(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;
    let coin_decimals = tf.wallet_service.chain_config().coin_decimals();

    let wallet_rpc = tf.rpc_client();

    // Create a new account
    let addr_result: Result<AddressInfo, _> =
        wallet_rpc.request("issue_address", [ACCOUNT1_ARG]).await;
    assert!(addr_result.is_err());
    let new_acct: NewAccountInfo =
        wallet_rpc.request("create_account", [EmptyArgs {}]).await.unwrap();
    assert_eq!(new_acct.account, 1);
    let acct1_addr: AddressInfo =
        wallet_rpc.request("issue_address", [ACCOUNT1_ARG]).await.unwrap();
    log::info!("acct1_addr: {acct1_addr:?}");

    // Get balance info
    let balances: Balances = wallet_rpc.request("get_balance", [ACCOUNT0_ARG]).await.unwrap();
    let coins_before = balances.coins().to_amount(coin_decimals).unwrap();
    log::info!("Balances: {balances:?}");
    let utxos: JsonValue = wallet_rpc.request("get_utxos", [ACCOUNT0_ARG]).await.unwrap();
    log::info!("UTXOs: {utxos:#}");
    let utxos = utxos.as_array().unwrap();
    assert_eq!(utxos.len(), 2);

    // Extract amount from the genesis UTXO
    let (utxo_amount, _outpoint0) = {
        let utxo0 = utxos[0].as_object().unwrap();
        let outpt = utxo0["outpoint"].as_object().unwrap();
        let id = outpt["id"].as_object().unwrap()["BlockReward"].as_str().unwrap();
        let index = outpt["index"].as_u64().unwrap();
        assert_eq!(index, 0);

        let output = &utxo0["output"].as_object().unwrap()["Transfer"].as_array().unwrap();
        let amount_val = &output[0].as_object().unwrap()["Coin"].as_object().unwrap()["val"];
        let amount = amount_val.as_u64().unwrap() as u128;

        let source_id: Id<Block> = wallet_test_node::decode_hex(id);
        let outpt = UtxoOutPoint::new(source_id.into(), index as u32);
        (amount, outpt)
    };

    // Check the balance and UTXO amount matches
    assert_eq!(utxo_amount, coins_before.into_atoms());

    let to_send_amount = Amount::from_atoms(utxo_amount / 2);
    let _: () = {
        let to_send_amount_str =
            to_send_amount.into_fixedpoint_str(tf.wallet_service.chain_config().coin_decimals());
        let send_to_addr = acct1_addr.address;
        let options = TransactionOptions { in_top_x_mb: 3 };
        let params = (ACCOUNT0_ARG, send_to_addr, to_send_amount_str, options);
        wallet_rpc.request("send_coins", params).await.unwrap()
    };

    let balances: Balances = wallet_rpc.request("get_balance", [ACCOUNT0_ARG]).await.unwrap();
    let coins_after = balances.coins().to_amount(coin_decimals).unwrap();
    assert!(coins_after <= (coins_before / 2).unwrap());
    assert!(coins_after >= (coins_before / 3).unwrap());

    let balances: Balances = wallet_rpc.request("get_balance", [ACCOUNT1_ARG]).await.unwrap();
    log::info!("acct1 balances: {balances:?}");

    tf.stop().await;
}

#[rstest]
#[ignore = "Translation of hexified values to bech32m not yet implemented"]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn no_hexified_destination(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;

    let wallet_rpc = tf.rpc_client();

    // Get balance info
    let utxos: JsonValue = wallet_rpc.request("get_utxos", [ACCOUNT0_ARG]).await.unwrap();
    log::debug!("UTXOs: {utxos:#}");
    let utxos_string = utxos.to_string();

    // Should not contain any "Hexified" values as these should have been converted to bech32m.
    assert!(!utxos_string.contains("Hexified"));

    tf.stop().await;
}

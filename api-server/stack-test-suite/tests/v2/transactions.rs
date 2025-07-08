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

use api_server_common::storage::storage_api::{
    block_aux_data::BlockAuxData, TransactionInfo, TxAdditionalInfo,
};
use api_web_server::api::json_helpers::to_tx_json_with_block_info;
use serde_json::Value;

use super::*;

#[tokio::test]
async fn invalid_offset() {
    let (task, response) = spawn_webserver("/api/v2/transaction?offset=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset");

    task.abort();
}

#[tokio::test]
async fn invalid_before_tx_global_index() {
    let (task, response) = spawn_webserver("/api/v2/transaction?offset_mode=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset mode");

    task.abort();
}

#[tokio::test]
async fn invalid_num_items() {
    let (task, response) = spawn_webserver("/api/v2/transaction?items=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid number of items");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn invalid_num_items_max(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let more_than_max = rng.gen_range(101..1000);
    let (task, response) =
        spawn_webserver(&format!("/api/v2/transaction?items={more_than_max}")).await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid number of items");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let n_blocks = rng.gen_range(3..100);
            let num_tx = rng.gen_range(2..n_blocks);

            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let chainstate_block_ids = tf
                    .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                    .unwrap();

                let mut num_txs: usize = chainstate_block_ids
                    .iter()
                    .map(|id| {
                        let block_id = tf.to_chain_block_id(id);
                        let block = tf.block(block_id);
                        block.transactions().len()
                    })
                    .sum();

                let txs: Vec<serde_json::Value> = chainstate_block_ids
                    .windows(2)
                    .rev()
                    .enumerate()
                    .map(|(idx, ids)| {
                        let block_id = tf.to_chain_block_id(&ids[1]);
                        let block = tf.block(block_id);
                        let prev_block = tf.block(tf.to_chain_block_id(&ids[0]));
                        let prev_tx = &prev_block.transactions()[0];

                        let transaction_index = rng.gen_range(0..block.transactions().len());
                        let signed_transaction = &block.transactions()[transaction_index];
                        let transaction = signed_transaction.transaction();

                        let utxos = transaction
                            .inputs()
                            .iter()
                            .map(|inp| match inp {
                                TxInput::Utxo(outpoint) => Some(
                                    prev_tx.outputs()[outpoint.output_index() as usize].clone(),
                                ),
                                TxInput::Account(_)
                                | TxInput::AccountCommand(_, _)
                                | TxInput::OrderAccountCommand(_) => None,
                            })
                            .collect();

                        let tx_global_index =
                            num_txs - block.transactions().len() + transaction_index;
                        num_txs -= block.transactions().len();
                        to_tx_json_with_block_info(
                            &TransactionInfo {
                                tx: signed_transaction.clone(),
                                additional_info: TxAdditionalInfo {
                                    input_utxos: utxos,
                                    fee: Amount::ZERO,
                                    token_decimals: BTreeMap::new(),
                                },
                            },
                            &chain_config,
                            BlockHeight::new(n_blocks as u64),
                            BlockAuxData::new(
                                block_id.into(),
                                BlockHeight::new((n_blocks - idx) as u64),
                                block.timestamp(),
                            ),
                            tx_global_index as u64,
                        )
                    })
                    .take(num_tx)
                    .collect();

                _ = tx.send(txs);

                chainstate_block_ids
                    .iter()
                    .map(|id| tf.block(tf.to_chain_block_id(id)))
                    .collect::<Vec<_>>()
            };

            let storage = {
                let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                let mut db_tx = storage.transaction_rw().await.unwrap();
                db_tx.reinitialize_storage(&chain_config).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            let chain_config = Arc::new(chain_config);
            let mut local_node = BlockchainState::new(Arc::clone(&chain_config), storage);
            local_node.scan_genesis(chain_config.genesis_block()).await.unwrap();
            local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config: Arc::clone(&chain_config),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((get_time(), vec![])),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, true).await
    });

    let expected_transactions = rx.await.unwrap();
    let num_tx = expected_transactions.len();

    let url = format!("/api/v2/transaction?offset=0&items={num_tx}");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("body: {}", body);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();

    assert_eq!(arr_body.len(), num_tx);
    for (expected_transaction, body) in expected_transactions.iter().zip(arr_body) {
        compare_body(body, expected_transaction);
    }

    let mut rng = make_seedable_rng(seed);
    let offset = rng.gen_range(1..num_tx);
    let items = num_tx - offset;
    let url = format!("/api/v2/transaction?offset={offset}&items={items}");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("body: {}", body);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();

    assert_eq!(arr_body.len(), num_tx - offset);
    for (expected_transaction, body) in expected_transactions[offset..].iter().zip(arr_body) {
        compare_body(body, expected_transaction);
    }

    // test before_tx_global_index instead of offset
    let tx_global_index = &expected_transactions[offset - 1]["tx_global_index"].as_str().unwrap();
    eprintln!("tx_global_index: '{tx_global_index}'");
    let url =
        format!("/api/v2/transaction?offset={tx_global_index}&items={items}&offset_mode=absolute");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("body: {}", body);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();

    assert_eq!(arr_body.len(), num_tx - offset);
    for (expected_transaction, body) in expected_transactions[offset..].iter().zip(arr_body) {
        compare_body(body, expected_transaction);
    }

    task.abort();
}

#[track_caller]
fn compare_body(body: &Value, expected_transaction: &Value) {
    assert_eq!(
        body.get("block_id").unwrap(),
        &expected_transaction["block_id"]
    );
    assert_eq!(
        body.get("version_byte").unwrap(),
        &expected_transaction["version_byte"]
    );
    assert_eq!(
        body.get("is_replaceable").unwrap(),
        &expected_transaction["is_replaceable"]
    );
    assert_eq!(body.get("flags").unwrap(), &expected_transaction["flags"]);
    assert_eq!(body.get("inputs").unwrap(), &expected_transaction["inputs"]);
    assert_eq!(
        body.get("outputs").unwrap(),
        &expected_transaction["outputs"]
    );
    assert_eq!(
        body.get("timestamp").unwrap(),
        &expected_transaction["timestamp"]
    );
    assert_eq!(
        body.get("confirmations").unwrap(),
        &expected_transaction["confirmations"]
    );
    assert_eq!(
        body.get("tx_global_index").unwrap(),
        &expected_transaction["tx_global_index"]
    );
}

// Copyright (c) 2025 RBB S.r.l
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

use api_web_server::api::json_helpers::tx_input_to_json;

use super::*;

#[tokio::test]
async fn invalid_transaction_id() {
    let (task, response) =
        spawn_webserver("/api/v2/transaction/invalid-transaction-id/output/1").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid transaction Id");

    task.abort();
}

#[tokio::test]
async fn transaction_not_found() {
    let (task, response) = spawn_webserver(
        "/api/v2/transaction/0000000000000000000000000000000000000000000000000000000000000001/output/1",
    )
    .await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Transaction output not found"
    );

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
            let block_height = rng.gen_range(2..50);
            let n_blocks = rng.gen_range(block_height..100);

            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let chainstate_block_ids = tf
                    .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                    .unwrap();

                // Need the "- 1" to account for the genesis block not in the vec
                let block_id = chainstate_block_ids[block_height - 1];
                let block = tf.block(tf.to_chain_block_id(&block_id));
                let prev_block =
                    tf.block(tf.to_chain_block_id(&chainstate_block_ids[block_height - 2]));
                let prev_tx = &prev_block.transactions()[0];

                let transaction_index = rng.gen_range(0..block.transactions().len());
                let transaction = block.transactions()[transaction_index].transaction();
                let transaction_id = transaction.get_id();

                let utxos = transaction.inputs().iter().map(|inp| match inp {
                    TxInput::Utxo(outpoint) => {
                        Some(prev_tx.outputs()[outpoint.output_index() as usize].clone())
                    }
                    TxInput::Account(_)
                    | TxInput::AccountCommand(_, _)
                    | TxInput::OrderAccountCommand(_) => None,
                });

                let expected_transaction = json!({
                "block_id": block_id.to_hash().encode_hex::<String>(),
                "timestamp": block.timestamp().to_string(),
                "confirmations": BlockHeight::new((n_blocks - block_height) as u64).to_string(),
                "version_byte": transaction.version_byte(),
                "is_replaceable": transaction.is_replaceable(),
                "flags": transaction.flags(),
                "inputs": transaction.inputs().iter().zip(utxos).map(|(inp, utxo)| json!({
                    "input": tx_input_to_json(inp, &TokenDecimals::Single(None), &chain_config),
                    "utxo": utxo.as_ref().map(|txo| txoutput_to_json(txo, &chain_config, &TokenDecimals::Single(None))),
                    })).collect::<Vec<_>>(),
                "outputs": transaction.outputs()
                            .iter()
                            .map(|out| txoutput_to_json(out, &chain_config, &TokenDecimals::Single(None)))
                            .collect::<Vec<_>>(),
                });

                _ = tx.send((
                    block_id.to_hash().encode_hex::<String>(),
                    transaction_id.to_hash().encode_hex::<String>(),
                    expected_transaction,
                ));

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

    let (block_id, transaction_id, expected_transaction) = rx.await.unwrap();
    let url = format!("/api/v2/transaction/{transaction_id}");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(body.get("block_id").unwrap(), &block_id);
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

    task.abort();
}

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

use super::*;

#[tokio::test]
async fn invalid_transaction_id() {
    let (task, response) = spawn_webserver("/api/v1/transaction/invalid-transaction-id").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid transaction Id");

    task.abort();
}

#[tokio::test]
async fn transaction_not_found() {
    let (task, response) = spawn_webserver(
        "/api/v1/transaction/0000000000000000000000000000000000000000000000000000000000000001",
    )
    .await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Transaction not found");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let block_height = rng.gen_range(1..50);
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

                let transaction_index = rng.gen_range(0..block.transactions().len());
                let transaction = block.transactions()[transaction_index].transaction();
                let transaction_id = transaction.get_id();

                let expected_transaction = json!({
                "block_id": block_id.to_hash().encode_hex::<String>(),
                "version_byte": transaction.version_byte(),
                "is_replaceable": transaction.is_replaceable(),
                "flags": transaction.flags(),
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
                db_tx.initialize_storage(&chain_config).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            let mut local_node = BlockchainState::new(storage);
            local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config: Arc::new(chain_config),
            }
        };

        web_server(listener, web_server_state).await
    });

    let (block_id, transaction_id, expected_transaction) = rx.await.unwrap();
    let url = format!("/api/v1/transaction/{transaction_id}");

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
        expected_transaction.get("version_byte").unwrap()
    );
    assert_eq!(
        body.get("is_replaceable").unwrap(),
        expected_transaction.get("is_replaceable").unwrap()
    );
    assert_eq!(
        body.get("flags").unwrap(),
        expected_transaction.get("flags").unwrap()
    );

    // TODO check inputs and outputs

    task.abort();
}

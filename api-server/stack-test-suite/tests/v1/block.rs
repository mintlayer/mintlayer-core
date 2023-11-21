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

use api_web_server::api::json_helpers::{tx_to_json, txoutput_to_json};

use super::*;

#[tokio::test]
async fn invalid_block_id() {
    let (task, response) = spawn_webserver("/api/v1/block/invalid-block-id").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");

    task.abort();
}

#[tokio::test]
async fn block_not_found() {
    let (task, response) = spawn_webserver(
        "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001",
    )
    .await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Block not found");

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

    let mut rng = make_seedable_rng(seed);
    let block_height = rng.gen_range(2..50);
    let task = tokio::spawn(async move {
        let web_server_state = {
            let n_blocks = rng.gen_range(block_height..100);

            let chain_config = create_unit_test_config();

            let storage = {
                let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                let mut db_tx = storage.transaction_rw().await.unwrap();
                db_tx.initialize_storage(&chain_config).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            // generate some n_blocks
            let mut tf =
                TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
            let chainstate_block_ids = tf
                .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                .unwrap();
            let chainstate_blocks = chainstate_block_ids
                .iter()
                .map(|id| tf.block(tf.to_chain_block_id(id)))
                .collect::<Vec<_>>();

            // Scan those blocks
            let chain_config = Arc::new(chain_config);
            let mut local_node = BlockchainState::new(chain_config.clone(), storage);
            local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

            // Get the current block at block_height
            // Need the "- 1" to account for the genesis block not in the vec
            let old_block_id = chainstate_block_ids[block_height - 1];
            let block = tf.block(tf.to_chain_block_id(&old_block_id));

            let old_expected_block = json!({
                "header": {
                    "previous_block_id": block.prev_block_id(),
                    "merkle_root": block.merkle_root(),
                    "witness_merkle_root": block.witness_merkle_root(),
                    "timestamp": block.timestamp(),
                },
                "body": {
                    "reward": block.block_reward()
                        .outputs()
                        .iter()
                        .map(|out| txoutput_to_json(out, &chain_config))
                        .collect::<Vec<_>>(),
                    "transactions": block.transactions()
                                        .iter()
                                        .map(|tx| tx_to_json(tx.transaction(), &chain_config))
                                        .collect::<Vec<_>>(),
                },
            });

            // create a reorg
            let parent_id = chainstate_block_ids[block_height - 2];
            let count = rng.gen_range(block_height..=100);
            tf.create_chain(&parent_id, count, &mut rng).unwrap();
            let new_chainstate_block_ids =
                tf.block_indexes.iter().skip(block_height - 2).map(|b| b.block_id());

            let new_chainstate_blocks =
                new_chainstate_block_ids.map(|id| tf.block(*id)).collect::<Vec<_>>();
            local_node
                .scan_blocks(
                    BlockHeight::new((block_height - 2) as u64),
                    new_chainstate_blocks,
                )
                .await
                .unwrap();

            // Need the "- 1" to account for the genesis block not in the vec
            let block_id = chainstate_block_ids[block_height - 1];
            let block = tf.block(tf.to_chain_block_id(&block_id));

            let new_expected_block = json!({
                "header": {
                    "previous_block_id": block.prev_block_id(),
                    "merkle_root": block.merkle_root(),
                    "witness_merkle_root": block.witness_merkle_root(),
                    "timestamp": block.timestamp(),
                },
                "body": {
                    "reward": block.block_reward()
                        .outputs()
                        .iter()
                        .map(|out| txoutput_to_json(out, &chain_config))
                        .collect::<Vec<_>>(),
                    "transactions": block.transactions()
                                        .iter()
                                        .map(|tx| tx_to_json(tx.transaction(), &chain_config))
                                        .collect::<Vec<_>>(),
                },
            });

            _ = tx.send((
                block_id.to_hash().encode_hex::<String>(),
                new_expected_block,
                old_block_id.to_hash().encode_hex::<String>(),
                old_expected_block,
            ));

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config,
            }
        };

        web_server(listener, web_server_state).await
    });

    let (block_id, new_expected_block, old_block_id, old_expected_block) = rx.await.unwrap();
    let url = format!("/api/v1/block/{block_id}");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body, new_expected_block);

    let url = format!("/api/v1/block/{old_block_id}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body, old_expected_block);
    task.abort();
}

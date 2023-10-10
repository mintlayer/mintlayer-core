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

use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::{ApiServerStorageWrite, ApiServerTransactionRw, Transactional},
};
use blockchain_scanner_lib::{
    blockchain_state::BlockchainState, sync::local_state::LocalBlockchainState,
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::config::create_unit_test_config,
    primitives::{BlockHeight, Idable},
};
use hex::ToHex;
use rstest::rstest;
use serde_json::json;
use std::{net::TcpListener, sync::Arc};
use test_utils::random::{make_seedable_rng, Rng, Seed};
use web_server::{api::web_server, ApiServerWebServerState};

async fn spawn_webserver(url: &str) -> (tokio::task::JoinHandle<()>, reqwest::Response) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            ApiServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
            }
        };

        web_server(listener, web_server_state).await.unwrap();
    });

    let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
        .await
        .unwrap();

    (task, response)
}

#[tokio::test]
async fn server_status() {
    let (task, response) = spawn_webserver("/").await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), r#"{"versions":["1.0.0"]}"#);

    task.abort();
}

#[tokio::test]
async fn bad_request() {
    let (task, response) = spawn_webserver("/non-existent-url").await;

    assert_eq!(response.status(), 400);
    assert_eq!(response.text().await.unwrap(), r#"{"error":"Bad request"}"#);

    task.abort();
}

mod v1_block {
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
        let socket = listener.local_addr().unwrap();

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

                    let expected_block = json!({
                        "previous_block_id": block.prev_block_id().to_hash().encode_hex::<String>(),
                        "timestamp": block.timestamp(),
                        "merkle_root": block.merkle_root().encode_hex::<String>(),
                    });

                    _ = tx.send((block_id.to_hash().encode_hex::<String>(), expected_block));

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

        let (block_id, expected_block) = rx.await.unwrap();
        let url = format!("/api/v1/block/{block_id}");

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_object().unwrap();

        assert_eq!(
            body.get("previous_block_id").unwrap(),
            &expected_block["previous_block_id"]
        );
        assert_eq!(body.get("timestamp").unwrap(), &expected_block["timestamp"]);
        assert_eq!(
            body.get("merkle_root").unwrap(),
            &expected_block["merkle_root"]
        );

        assert!(body.contains_key("transactions"));

        // TODO check transactions fields
        // assert...

        task.abort();
    }
}

mod v1_block_header {
    use super::*;

    #[tokio::test]
    async fn invalid_block_id() {
        let (task, response) = spawn_webserver("/api/v1/block/invalid-block-id/header").await;

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");

        task.abort();
    }

    #[tokio::test]
    async fn block_not_found() {
        let (task, response) = spawn_webserver(
            "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001/header",
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
        let socket = listener.local_addr().unwrap();

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

                    let expected_block = json!({
                        "previous_block_id": block.prev_block_id().to_hash().encode_hex::<String>(),
                        "timestamp": block.timestamp(),
                        "merkle_root": block.merkle_root().encode_hex::<String>(),
                    });

                    _ = tx.send((block_id.to_hash().encode_hex::<String>(), expected_block));

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

        let (block_id, expected_block) = rx.await.unwrap();
        let url = format!("/api/v1/block/{block_id}/header");

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_object().unwrap();

        assert_eq!(
            body.get("previous_block_id").unwrap(),
            &expected_block["previous_block_id"]
        );
        assert_eq!(body.get("timestamp").unwrap(), &expected_block["timestamp"]);
        assert_eq!(
            body.get("merkle_root").unwrap(),
            &expected_block["merkle_root"]
        );

        assert!(!body.contains_key("transactions"));

        task.abort();
    }
}

mod v1_block_reward {
    use super::*;

    #[tokio::test]
    async fn invalid_block_id() {
        let (task, response) = spawn_webserver("/api/v1/block/invalid-block-id/reward").await;

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");

        task.abort();
    }

    #[tokio::test]
    async fn block_not_found() {
        let (task, response) = spawn_webserver(
            "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001/reward",
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
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn({
            async move {
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
                            .create_chain_return_ids(
                                &tf.genesis().get_id().into(),
                                n_blocks,
                                &mut rng,
                            )
                            .unwrap();

                        // Need the "- 1" to account for the genesis block not in the vec
                        let block_id = chainstate_block_ids[block_height - 1];
                        let block = tf.block(tf.to_chain_block_id(&block_id));
                        let expected_block_reward = block.block_reward().clone();

                        _ = tx.send((
                            block_id.to_hash().encode_hex::<String>(),
                            expected_block_reward,
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
            }
        });

        let (block_id, _expected_block_reward) = rx.await.unwrap();
        let url = format!("/api/v1/block/{block_id}/reward");

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let _body = body.as_object().unwrap();

        // TODO check block reward fields
        // assert...

        task.abort();
    }
}

mod v1_block_transaction_ids {
    use super::*;

    #[tokio::test]
    async fn invalid_block_id() {
        let (task, response) =
            spawn_webserver("/api/v1/block/invalid-block-id/transaction-ids").await;

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");

        task.abort();
    }

    #[tokio::test]
    async fn block_not_found() {
        let (task, response) = spawn_webserver(
	    "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001/transaction-ids").await;

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
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn({
            async move {
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
                            .create_chain_return_ids(
                                &tf.genesis().get_id().into(),
                                n_blocks,
                                &mut rng,
                            )
                            .unwrap();

                        // Need the "- 1" to account for the genesis block not in the vec
                        let block_id = chainstate_block_ids[block_height - 1];

                        let expected_transaction_ids = tf
                            .block(tf.to_chain_block_id(&block_id))
                            .transactions()
                            .iter()
                            .map(|tx| tx.transaction().get_id())
                            .collect::<Vec<_>>();

                        _ = tx.send((
                            block_id.to_hash().encode_hex::<String>(),
                            expected_transaction_ids,
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
            }
        });

        let (block_id, expected_transaction_ids) = rx.await.unwrap();
        let url = format!("/api/v1/block/{block_id}/transaction-ids");

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        let body_transaction_ids =
            body.as_object().unwrap().get("transaction_ids").unwrap().as_array().unwrap();

        for transaction_id in expected_transaction_ids {
            assert!(body_transaction_ids
                .contains(&json!(transaction_id.to_hash().encode_hex::<String>())));
        }

        task.abort();
    }
}

#[tokio::test]
async fn v1_chain_genesis() {
    let url = "/api/v1/chain/genesis";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn({
        async move {
            let web_server_state = {
                let chain_config = Arc::new(create_unit_test_config());
                let expected_genesis = chain_config.genesis_block().clone();

                _ = tx.send(expected_genesis);

                let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                ApiServerWebServerState {
                    db: Arc::new(storage),
                    chain_config: Arc::clone(&chain_config),
                }
            };

            web_server(listener, web_server_state).await
        }
    });

    let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let expected_genesis = rx.await.unwrap();

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["block_id"].as_str().unwrap(),
        expected_genesis.get_id().to_hash().encode_hex::<String>()
    );

    task.abort();
}

mod v1_chain_at_height {
    use super::*;

    #[tokio::test]
    async fn invalid_height() {
        let (task, response) = spawn_webserver("/api/v1/chain/invalid-height").await;

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block height");

        task.abort();
    }

    #[tokio::test]
    async fn height_zero() {
        let (task, response) = spawn_webserver("/api/v1/chain/0").await;

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            body["error"].as_str().unwrap(),
            "No block found at supplied height"
        );

        task.abort();
    }

    #[tokio::test]
    async fn height_past_tip() {
        let (task, response) = spawn_webserver("/api/v1/chain/1337").await;

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            body["error"].as_str().unwrap(),
            "No block found at supplied height"
        );

        task.abort();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn height_n(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let block_height = rng.gen_range(1..50);
        let n_blocks = rng.gen_range(block_height..100);
        let url = format!("/api/v1/chain/{block_height}");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = create_unit_test_config();

                    let chainstate_blocks = {
                        let mut tf = TestFramework::builder(&mut rng)
                            .with_chain_config(chain_config.clone())
                            .build();

                        let chainstate_block_ids = tf
                            .create_chain_return_ids(
                                &tf.genesis().get_id().into(),
                                n_blocks,
                                &mut rng,
                            )
                            .unwrap();

                        // Need the "- 1" to account for the genesis block not in the vec
                        let expected_block_id = chainstate_block_ids[block_height - 1];

                        _ = tx.send(expected_block_id);

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
            }
        });

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let expected_block_id = rx.await.unwrap();

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            body.as_str().unwrap(),
            expected_block_id.to_hash().encode_hex::<String>()
        );

        task.abort();
    }
}

mod v1_chain_tip {
    use super::*;

    #[tokio::test]
    async fn at_genesis() {
        let url = "/api/v1/chain/tip";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let binding = Arc::clone(&chain_config);
                    let expected_genesis_id = binding.genesis_block().get_id();

                    _ = tx.send(expected_genesis_id);

                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    ApiServerWebServerState {
                        db: Arc::new(storage),
                        chain_config: chain_config.clone(),
                    }
                };

                web_server(listener, web_server_state).await
            }
        });

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let expected_genesis_id = rx.await.unwrap();

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["block_height"].as_u64().unwrap(), 0);

        assert_eq!(
            body["block_id"].as_str().unwrap(),
            expected_genesis_id.to_hash().encode_hex::<String>()
        );

        task.abort();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn height_n(#[case] seed: Seed) {
        let url = "/api/v1/chain/tip";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn({
            async move {
                let mut rng = make_seedable_rng(seed);
                let n_blocks = rng.gen_range(1..100);

                let web_server_state = {
                    let chain_config = create_unit_test_config();

                    let chainstate_blocks = {
                        let mut tf = TestFramework::builder(&mut rng)
                            .with_chain_config(chain_config.clone())
                            .build();

                        let chainstate_block_ids = tf
                            .create_chain_return_ids(
                                &tf.genesis().get_id().into(),
                                n_blocks,
                                &mut rng,
                            )
                            .unwrap();

                        // Need the "- 1" to account for the genesis block not in the vec
                        let expected_block_id = chainstate_block_ids[n_blocks - 1];

                        _ = tx.send((n_blocks, expected_block_id));

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
            }
        });

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let (height, expected_block_id) = rx.await.unwrap();

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let _body = body.as_object().unwrap();

        assert_eq!(body["block_height"].as_u64().unwrap(), height as u64);

        assert_eq!(
            body["block_id"].as_str().unwrap(),
            expected_block_id.to_hash().encode_hex::<String>()
        );

        task.abort();
    }
}

mod v1_transaction {
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
        let socket = listener.local_addr().unwrap();

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

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
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
}

mod v1_transaction_merkle_path {
    use super::*;

    #[tokio::test]
    async fn get_transaction_failed() {
        let (task, response) =
            spawn_webserver("/api/v1/transaction/invalid-txid/merkle-path").await;

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid transaction Id");

        task.abort();
    }

    // TODO I wanted to delete the block from the database so that
    // get_block() fails within transaction_merkle_path(). However it
    // looks like the block is not being deleted
    //
    // #[rstest]
    // #[trace]
    // #[case(Seed::from_entropy())]
    // #[tokio::test]
    // async fn get_block_failed(#[case] seed: Seed) {
    //     let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    //     let socket = listener.local_addr().unwrap();

    //     let (tx, rx) = tokio::sync::oneshot::channel();

    //     let task = tokio::spawn(async move {
    //         let web_server_state = {
    //             let mut rng = make_seedable_rng(seed);
    //             let block_height = rng.gen_range(1..50);
    //             let n_blocks = rng.gen_range(block_height..100);

    //             let chain_config = create_unit_test_config();

    //             let chainstate_blocks = {
    //                 let mut tf = TestFramework::builder(&mut rng)
    //                     .with_chain_config(chain_config.clone())
    //                     .build();

    //                 let chainstate_block_ids = tf
    //                     .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
    //                     .unwrap();

    //                 // Need the "- 1" to account for the genesis block not in the vec
    //                 let block_id = chainstate_block_ids[block_height - 1];

    //                 let block = tf.block(tf.to_chain_block_id(&block_id));

    //                 let transaction_index = rng.gen_range(0..block.transactions().len());
    //                 let transaction = block.transactions()[transaction_index].transaction();
    //                 let transaction_id = transaction.get_id();

    //                 _ = tx.send(transaction_id.to_hash().encode_hex::<String>());

    //                 chainstate_block_ids
    //                     .iter()
    //                     .map(|id| tf.block(tf.to_chain_block_id(id)))
    //                     .collect::<Vec<_>>()
    //             };

    //             let mut storage = {
    //                 let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

    //                 let mut db_tx = storage.transaction_rw().await.unwrap();
    //                 db_tx.initialize_storage(&chain_config).await.unwrap();
    //                 db_tx.commit().await.unwrap();

    //                 storage
    //             };

    //             let mut local_node = BlockchainState::new(storage);
    //             local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

    //             storage = local_node.storage().clone_storage().await;

    //             {
    //                 let mut db_tx = storage.transaction_rw().await.unwrap();

    //                 db_tx
    //                     .del_main_chain_block_id(BlockHeight::new(
    //                         (block_height - 1).try_into().unwrap(),
    //                     ))
    //                     .await
    //                     .unwrap();

    //                 db_tx.commit().await.unwrap();
    //             }

    //             ApiServerWebServerState {
    //                 db: Arc::new(storage),
    //                 chain_config: Arc::new(chain_config),
    //             }
    //         };

    //         web_server(listener, web_server_state).await
    //     });

    //     let transaction_id = rx.await.unwrap();
    //     let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

    //     let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
    //         .await
    //         .unwrap();

    //     assert_eq!(response.status(), 400);

    //     let body = response.text().await.unwrap();
    //     let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    //     let body = body.as_object().unwrap();

    //     assert_eq!(body["error"].as_str().unwrap(), "Block not found");

    // 	task.abort();
    // }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn transaction_not_part_of_block(#[case] seed: Seed) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            let web_server_state = {
                let mut rng = make_seedable_rng(seed);
                let block_height = rng.gen_range(1..50);
                let n_blocks = rng.gen_range(block_height..100);

                let chain_config = create_unit_test_config();

                let (chainstate_blocks, signed_transaction, transaction_id) = {
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

                    _ = tx.send(transaction_id.to_hash().encode_hex::<String>());

                    (
                        chainstate_block_ids
                            .iter()
                            .map(|id| tf.block(tf.to_chain_block_id(id)))
                            .collect::<Vec<_>>(),
                        block.transactions()[transaction_index].clone(),
                        transaction_id,
                    )
                };

                let mut storage = {
                    let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    let mut db_tx = storage.transaction_rw().await.unwrap();
                    db_tx.initialize_storage(&chain_config).await.unwrap();
                    db_tx.commit().await.unwrap();

                    storage
                };

                let mut local_node = BlockchainState::new(storage);
                local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

                storage = local_node.storage().clone_storage().await;

                {
                    // TODO to test this I wanted to delete the block
                    // from the database so that get_block() fails
                    // within transaction_merkle_path(). However it
                    // looks like this isn't deleting the block

                    let mut db_tx = storage.transaction_rw().await.unwrap();

                    db_tx.set_transaction(transaction_id, None, &signed_transaction).await.unwrap();

                    db_tx.commit().await.unwrap();
                }

                ApiServerWebServerState {
                    db: Arc::new(storage),
                    chain_config: Arc::new(chain_config),
                }
            };

            web_server(listener, web_server_state).await
        });

        let transaction_id = rx.await.unwrap();
        let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_object().unwrap();

        assert_eq!(
            body["error"].as_str().unwrap(),
            "Transaction not part of any block"
        );

        task.abort();
    }

    // TODO tests for:
    //
    // - CannotFindTransactionInBlock
    // - TransactionIndexOverflow
    // - ErrorCalculatingMerkleTree
    // - ErrorCalcutingMerklePath

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn ok(#[case] seed: Seed) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

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

                    let merkle_proxy = block.body().merkle_tree_proxy().unwrap();
                    let merkle_tree = merkle_proxy
                        .merkle_tree()
                        .transaction_inclusion_proof(transaction_index.try_into().unwrap())
                        .unwrap()
                        .into_hashes();

                    let expected_transaction = json!({
                    "block_id": block_id.to_hash().encode_hex::<String>(),
                    "transaction_index": transaction_index,
                    "merkle_root": block.merkle_root().encode_hex::<String>(),
                    "merkle_path": merkle_tree.into_iter().map(
                        |hash| hash.encode_hex::<String>()).collect::<Vec<_>>(),
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
        let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

        let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_object().unwrap();

        assert_eq!(body.get("block_id").unwrap(), &block_id);
        assert_eq!(
            body.get("transaction_index").unwrap(),
            expected_transaction.get("transaction_index").unwrap()
        );
        assert_eq!(
            body.get("merkle_root").unwrap(),
            expected_transaction.get("merkle_root").unwrap()
        );

        for (index, hash) in body.get("merkle_path").unwrap().as_array().unwrap().iter().enumerate()
        {
            assert_eq!(
                hash,
                expected_transaction.get("merkle_path").unwrap().get(index).unwrap()
            );
        }

        task.abort();
    }
}

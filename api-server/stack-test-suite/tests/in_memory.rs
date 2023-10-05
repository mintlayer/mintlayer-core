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
use web_server::{api::web_server, APIServerWebServerState};

#[tokio::test]
async fn server_status() {
    let url = "/";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            APIServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
            }
        };

        web_server(listener, web_server_state).await
    });

    let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), r#"{"versions":["1.0.0"]}"#);
}

#[tokio::test]
async fn bad_request() {
    let url = "/non-existent-url";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            APIServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
            }
        };

        web_server(listener, web_server_state).await
    });

    let response = reqwest::get(format!("http://{}:{}{url}", socket.ip(), socket.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    assert_eq!(response.text().await.unwrap(), r#"{"error":"Bad request"}"#);
}

mod v1_block {
    use super::*;

    #[tokio::test]
    async fn invalid_block_id() {
        let url = "/api/v1/block/invalid-block-id";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");
    }

    #[tokio::test]
    async fn block_not_found() {
        let url = "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Block not found");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn ok(#[case] seed: Seed) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn({
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

                    APIServerWebServerState {
                        db: Arc::new(local_node.storage().clone_storage().await),
                        chain_config: Arc::new(chain_config),
                    }
                };

                web_server(listener, web_server_state).await
            }
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
    }
}

mod v1_block_header {
    use super::*;

    #[tokio::test]
    async fn invalid_block_id() {
        let url = "/api/v1/block/invalid-block-id/header";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");
    }

    #[tokio::test]
    async fn block_not_found() {
        let url =
            "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001/header";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Block not found");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn ok(#[case] seed: Seed) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn({
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

                    APIServerWebServerState {
                        db: Arc::new(local_node.storage().clone_storage().await),
                        chain_config: Arc::new(chain_config),
                    }
                };

                web_server(listener, web_server_state).await
            }
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
    }
}

mod v1_block_reward {
    use super::*;

    #[tokio::test]
    async fn invalid_block_id() {
        let url = "/api/v1/block/invalid-block-id/reward";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");
    }

    #[tokio::test]
    async fn block_not_found() {
        let url =
            "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001/reward";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Block not found");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn ok(#[case] seed: Seed) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn({
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

                    APIServerWebServerState {
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
    }
}

mod v1_block_transaction_ids {
    use super::*;

    #[tokio::test]
    async fn invalid_block_id() {
        let url = "/api/v1/block/invalid-block-id/transaction-ids";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");
    }

    #[tokio::test]
    async fn block_not_found() {
        let url = "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001/transaction-ids";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Block not found");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn ok(#[case] seed: Seed) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn({
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

                    APIServerWebServerState {
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
    }
}

#[tokio::test]
async fn v1_chain_genesis() {
    let url = "/api/v1/chain/genesis";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn({
        async move {
            let web_server_state = {
                let chain_config = Arc::new(create_unit_test_config());
                let expected_genesis = chain_config.genesis_block().clone();

                _ = tx.send(expected_genesis);

                let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                APIServerWebServerState {
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
}

mod v1_chain_at_height {
    use super::*;

    #[tokio::test]
    async fn invalid_height() {
        let url = "/api/v1/chain/invalid-height";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body["error"].as_str().unwrap(), "Invalid block height");
    }

    #[tokio::test]
    async fn height_zero() {
        let url = "/api/v1/chain/0";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            body["error"].as_str().unwrap(),
            "No block found at supplied height"
        );
    }

    #[tokio::test]
    async fn height_past_tip() {
        let url = "/api/v1/chain/1337";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = listener.local_addr().unwrap();

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        assert_eq!(response.status(), 400);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            body["error"].as_str().unwrap(),
            "No block found at supplied height"
        );
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

        tokio::spawn({
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

                    APIServerWebServerState {
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

        tokio::spawn({
            async move {
                let web_server_state = {
                    let chain_config = Arc::new(create_unit_test_config());
                    let binding = Arc::clone(&chain_config);
                    let expected_genesis_id = binding.genesis_block().get_id();

                    _ = tx.send(expected_genesis_id);

                    let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    APIServerWebServerState {
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

        tokio::spawn({
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

                    APIServerWebServerState {
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
    }
}

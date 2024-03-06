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

use std::sync::RwLock;

use api_web_server::{api::json_helpers::txoutput_to_json, CachedValues};
use common::primitives::time::get_time;

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_block_id() {
    let (task, response) = spawn_webserver("/api/v2/block/invalid-block-id/reward").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");

    task.abort();
}

#[tokio::test]
async fn block_not_found() {
    let (task, response) = spawn_webserver(
        "/api/v2/block/0000000000000000000000000000000000000000000000000000000000000001/reward",
    )
    .await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Block not found");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn no_reward(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

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
                        .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                        .unwrap();

                    // Need the "- 1" to account for the genesis block not in the vec
                    let block_id = chainstate_block_ids[block_height - 1];

                    _ = tx.send(block_id.to_hash().encode_hex::<String>());

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
        }
    });

    let block_id = rx.await.unwrap();
    let url = format!("/api/v2/block/{block_id}/reward");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_array().unwrap();

    assert!(body.is_empty());

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn has_reward(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn({
        async move {
            let web_server_state = {
                let mut rng = make_seedable_rng(seed);

                let chain_config = create_unit_test_config();

                let block = {
                    let mut tf = TestFramework::builder(&mut rng)
                        .with_chain_config(chain_config.clone())
                        .build();

                    let genesis_id = tf.genesis().get_id();

                    let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                    let block = tf
                        .make_block_builder()
                        .with_parent(genesis_id.into())
                        .with_reward(vec![TxOutput::LockThenTransfer(
                            OutputValue::Coin(Amount::from_atoms(100)),
                            Destination::PublicKey(pk),
                            OutputTimeLock::ForBlockCount(0),
                        )])
                        .build();

                    let block_index =
                        tf.process_block(block.clone(), BlockSource::Local).unwrap().unwrap();

                    _ = tx.send((
                        block_index.block_id().to_hash().encode_hex::<String>(),
                        block
                            .block_reward()
                            .outputs()
                            .iter()
                            .map(|out| {
                                txoutput_to_json(out, &chain_config, &TokenDecimals::Single(None))
                            })
                            .collect::<serde_json::Value>(),
                    ));

                    block
                };

                let storage = {
                    let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                    let mut db_tx = storage.transaction_rw().await.unwrap();
                    db_tx.initialize_storage(&chain_config).await.unwrap();
                    db_tx.commit().await.unwrap();

                    storage
                };

                let chain_config = Arc::new(chain_config);
                let mut local_node = BlockchainState::new(Arc::clone(&chain_config), storage);
                local_node.scan_genesis(chain_config.genesis_block()).await.unwrap();
                local_node.scan_blocks(BlockHeight::new(0), vec![block]).await.unwrap();

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
        }
    });

    let (block_id, expected_reward) = rx.await.unwrap();
    let url = format!("/api/v2/block/{block_id}/reward");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body, expected_reward);

    task.abort();
}

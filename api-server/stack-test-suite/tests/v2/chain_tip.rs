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

use api_web_server::CachedValues;
use common::primitives::time::get_time;

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn at_genesis() {
    let url = "/api/v2/chain/tip";

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn({
        async move {
            let web_server_state = {
                let chain_config = Arc::new(create_unit_test_config());
                let binding = Arc::clone(&chain_config);
                let expected_genesis_id = binding.genesis_block().get_id();

                _ = tx.send(json!({
                    "block_height": 0,
                    "block_id": expected_genesis_id.to_hash().encode_hex::<String>(),
                }));

                let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                ApiServerWebServerState {
                    db: Arc::new(storage),
                    chain_config: chain_config.clone(),
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

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    let expected_tip = rx.await.unwrap();

    assert_eq!(body, expected_tip);

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn height_n(#[case] seed: Seed) {
    let url = "/api/v2/chain/tip";

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

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
                        .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                        .unwrap();

                    // Need the "- 1" to account for the genesis block not in the vec
                    let expected_block_id = chainstate_block_ids[n_blocks - 1];

                    _ = tx.send(json!({
                    "block_height": n_blocks,
                    "block_id": expected_block_id,
                    }));

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
        }
    });

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    let expected_tip = rx.await.unwrap();

    assert_eq!(body, expected_tip);

    task.abort();
}

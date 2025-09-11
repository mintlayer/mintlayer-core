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

use std::sync::RwLock;

use itertools::Itertools as _;

use api_web_server::{
    api::v2::{DEFAULT_NUM_ITEMS, MAX_NUM_ITEMS},
    CachedValues,
};
use chainstate_test_framework::get_pos_target;
use common::primitives::time::get_time;
use test_utils::assert_matches_return_val;

use crate::{v2::utils::create_chain, DummyRPC};

use super::*;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed, #[values(false, true)] use_pos: bool) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut rng = make_seedable_rng(seed);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let inner_rng_seed = rng.gen();

    let task = tokio::spawn({
        async move {
            let mut rng = make_seedable_rng(inner_rng_seed);
            let blocks_count = rng.gen_range(10..100);

            let web_server_state = {
                let (chain_config, chainstate_blocks) =
                    create_chain(blocks_count, use_pos, &mut rng);
                let genesis_id = chain_config.genesis_block().get_id();
                let genesis_timestamp = chain_config.genesis_block().timestamp();

                let expected_jsons = std::iter::once(json!({
                    "block_height": 0,
                    "block_id": genesis_id.to_hash().encode_hex::<String>(),
                    "target": null,
                    "timestamp": genesis_timestamp.as_int_seconds()
                }))
                .chain(chainstate_blocks.iter().enumerate().map(|(idx, block)| {
                    let expected_target = use_pos.then(|| {
                        let target = get_pos_target(block).unwrap();
                        format!("0x{target:x}")
                    });
                    json!({
                        "block_height": idx + 1,
                        "block_id": block.get_id(),
                        "target": expected_target,
                        "timestamp": block.timestamp().as_int_seconds()
                    })
                }))
                .collect_vec();

                _ = tx.send(expected_jsons);

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

    let all_expected_jsons = rx.await.unwrap();
    // Total blocks count, including genesis.
    let total_blocks_count = all_expected_jsons.len();

    // Request all blocks
    {
        let url = format!("/api/v2/chain?offset=0&items={total_blocks_count}");
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let response = array_from_response(response).await;
        assert_eq!(response, all_expected_jsons);
    }

    // Request only the genesis
    {
        let url = "/api/v2/chain?offset=0&items=1";
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let response = array_from_response(response).await;
        assert_eq!(&response, &all_expected_jsons[..1]);
    }

    // Request without params
    {
        let url = "/api/v2/chain";
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let response = array_from_response(response).await;
        assert_eq!(&response, &all_expected_jsons[..DEFAULT_NUM_ITEMS as usize]);
    }

    // Request random number of blocks
    {
        let offset = rng.gen_range(0..=total_blocks_count);
        let items = rng.gen_range(0..=total_blocks_count);
        let url = format!("/api/v2/chain?offset={offset}&items={items}");
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let response = array_from_response(response).await;
        let end_idx = std::cmp::min(offset + items, all_expected_jsons.len());
        assert_eq!(&response, &all_expected_jsons[offset..end_idx]);
    }

    task.abort();
}

#[tokio::test]
async fn invalid_offset() {
    let (task, response) = spawn_webserver("/api/v2/chain?offset=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset");

    task.abort();
}

#[tokio::test]
async fn invalid_num_items() {
    let (task, response) = spawn_webserver("/api/v2/chain?items=asd").await;

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
    let more_than_max = rng.gen_range(MAX_NUM_ITEMS + 1..MAX_NUM_ITEMS * 2);
    let (task, response) = spawn_webserver(&format!("/api/v2/chain?items={more_than_max}")).await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid number of items");

    task.abort();
}

async fn array_from_response(response: reqwest::Response) -> Vec<serde_json::Value> {
    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_matches_return_val!(body, serde_json::Value::Array(array), array)
}

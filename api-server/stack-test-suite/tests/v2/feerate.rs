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

use api_web_server::{CachedValues, TxSubmitClient};
use common::primitives::time::get_time;
use mempool::FeeRate;
use node_comm::rpc_client::NodeRpcError;
use test_utils::mock_time_getter::mocked_time_getter_seconds;
use utils::atomics::SeqCstAtomicU64;

use super::*;

#[rstest]
#[trace]
#[tokio::test]
async fn invalid_query_parameter() {
    let (task, response) = spawn_webserver("/api/v2/feerate?in_top_x_mb=invalid").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Invalid in top X MB query parameter"
    );

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let in_top_x_mb = rng.gen_range(1..100);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            ApiServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((
                        get_time(),
                        vec![
                            (1, FeeRate::from_amount_per_kb(Amount::from_atoms(1))),
                            (100, FeeRate::from_amount_per_kb(Amount::from_atoms(100))),
                        ],
                    )),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, true).await.unwrap();
    });

    let response = reqwest::get(format!(
        "http://{}:{}/api/v2/feerate?in_top_x_mb={in_top_x_mb}",
        addr.ip(),
        addr.port()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    assert_eq!(body, format!("\"{in_top_x_mb}\""));

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok_reload_feerate(#[case] seed: Seed) {
    struct DummyRPC2 {}

    #[async_trait::async_trait]
    impl TxSubmitClient for DummyRPC2 {
        async fn submit_tx(&self, _: SignedTransaction) -> Result<(), NodeRpcError> {
            Ok(())
        }

        async fn get_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, NodeRpcError> {
            Ok(vec![
                (1, FeeRate::from_amount_per_kb(Amount::from_atoms(2))),
                (100, FeeRate::from_amount_per_kb(Amount::from_atoms(200))),
            ])
        }
    }
    let mut rng = make_seedable_rng(seed);
    let in_top_x_mb = rng.gen_range(1..100);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let seconds = Arc::new(SeqCstAtomicU64::new(12345));
    let time_getter = mocked_time_getter_seconds(Arc::clone(&seconds));

    let task = tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            ApiServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
                rpc: Arc::new(DummyRPC2 {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((
                        time_getter.get_time(),
                        vec![
                            (1, FeeRate::from_amount_per_kb(Amount::from_atoms(1))),
                            (100, FeeRate::from_amount_per_kb(Amount::from_atoms(100))),
                        ],
                    )),
                }),
                time_getter,
            }
        };

        web_server(listener, web_server_state, true).await.unwrap();
    });

    const REFRESH_INTERVAL_SEC: u64 = 30;
    let mut time_passed = 0;

    while time_passed <= REFRESH_INTERVAL_SEC {
        let response = reqwest::get(format!(
            "http://{}:{}/api/v2/feerate?in_top_x_mb={in_top_x_mb}",
            addr.ip(),
            addr.port()
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        assert_eq!(body, format!("\"{in_top_x_mb}\""));

        let sec_to_pass = rng.gen_range(1..REFRESH_INTERVAL_SEC);
        seconds.fetch_add(sec_to_pass);
        time_passed += sec_to_pass;
    }

    // after the refresh interval we will get the new feerates
    let response = reqwest::get(format!(
        "http://{}:{}/api/v2/feerate?in_top_x_mb={in_top_x_mb}",
        addr.ip(),
        addr.port()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let new_feerate = in_top_x_mb * 2;
    assert_eq!(body, format!("\"{new_feerate}\""));

    task.abort();
}

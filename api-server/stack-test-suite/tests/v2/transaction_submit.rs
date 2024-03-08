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

use chainstate_test_framework::empty_witness;
use common::{chain::UtxoOutPoint, primitives::H256};
use serialization::hex_encoded::HexEncoded;

use super::*;

#[rstest]
#[trace]
#[tokio::test]
async fn dissabled_post_route() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let url = "/api/v2/transaction";

    let task = tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            ApiServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((get_time(), vec![])),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, false).await.unwrap();
    });

    let body = "invalid transaction bytes";

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::Client::new()
        .post(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Forbidden endpoint");

    task.abort();
}

#[rstest]
#[trace]
#[tokio::test]
async fn invalid_transaction() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let url = "/api/v2/transaction";

    let task = tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            ApiServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((get_time(), vec![])),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, true).await.unwrap();
    });

    let body = "invalid transaction bytes";

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::Client::new()
        .post(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Invalid signed transaction"
    );

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let url = "/api/v2/transaction";

    let mut rng = make_seedable_rng(seed);

    let task = tokio::spawn(async move {
        let web_server_state = {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

            ApiServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::clone(&chain_config),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((get_time(), vec![])),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, true).await.unwrap();
    });

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(&mut rng))),
                0,
            )),
            empty_witness(&mut rng),
        )
        .build();

    let tx_id = tx.transaction().get_id().to_hash().encode_hex::<String>();

    let hex_tx: HexEncoded<SignedTransaction> = tx.into();
    let body = hex_tx.to_string();

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();
    assert_eq!(body.get("tx_id").unwrap(), &tx_id);

    task.abort();
}

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

use chainstate_test_framework::empty_witness;
use common::chain::UtxoOutPoint;

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
            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let genesis_outpoint = UtxoOutPoint::new(tf.best_block_id().into(), 0);

                // Transfer 1
                let tx1 = TransactionBuilder::new()
                    .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(2)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build();
                let tx1_id = tx1.transaction().get_id();
                let block1 = tf.make_block_builder().add_transaction(tx1).build(&mut rng);

                tf.process_block(block1.clone(), chainstate::BlockSource::Local).unwrap();

                // Spend one of the outputs
                let tx2 = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(tx1_id.into(), 0),
                        empty_witness(&mut rng),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(1))))
                    .build();

                let block2 = tf.make_block_builder().add_transaction(tx2).build(&mut rng);

                tf.process_block(block2.clone(), chainstate::BlockSource::Local).unwrap();

                _ = tx.send(tx1_id.to_hash().encode_hex::<String>());

                vec![block1, block2]
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

    let transaction_id = rx.await.unwrap();
    let url = format!("/api/v2/transaction/{transaction_id}/output/0");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();
    let chain_config = create_unit_test_config();

    assert_eq!(body.get("type").unwrap().as_str().unwrap(), "Transfer");
    assert_eq!(
        body.get("destination").unwrap().as_str().unwrap(),
        Address::new(&chain_config, Destination::AnyoneCanSpend).unwrap().as_str()
    );
    assert_eq!(
        body.get("spent_at_block_height").unwrap().as_number().unwrap(),
        &(2.into())
    );

    // Test the second output is not spent
    let url = format!("/api/v2/transaction/{transaction_id}/output/1");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();
    let chain_config = create_unit_test_config();

    assert_eq!(body.get("type").unwrap().as_str().unwrap(), "Transfer");
    assert_eq!(
        body.get("destination").unwrap().as_str().unwrap(),
        Address::new(&chain_config, Destination::AnyoneCanSpend).unwrap().as_str()
    );
    assert!(body.get("spent_at_block_height").unwrap().is_null());

    task.abort();
}

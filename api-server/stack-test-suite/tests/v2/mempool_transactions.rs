// Copyright (c) 2026 RBB S.r.l
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

use std::borrow::Cow;

use serde_json::Value;

use api_web_server::api::json_helpers::tx_input_to_json;

use super::*;

#[tokio::test]
async fn invalid_offset() {
    let (task, response) = spawn_webserver("/api/v2/mempool/transaction?offset=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset");

    task.abort();
}

#[tokio::test]
async fn invalid_num_items() {
    let (task, response) = spawn_webserver("/api/v2/mempool/transaction?items=asd").await;

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
    let more_than_max = rng.gen_range(101..1000);
    let (task, response) = spawn_webserver(&format!(
        "/api/v2/mempool/transaction?items={more_than_max}"
    ))
    .await;

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
async fn ok(#[case] seed: Seed) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let num_tx = rng.gen_range(2..20);

            let chain_config = create_unit_test_config();

            let storage = {
                let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                let mut db_tx = storage.transaction_rw().await.unwrap();
                db_tx.reinitialize_storage(&chain_config).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            let mut tf =
                TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();

            let chain_config_arc = Arc::new(chain_config.clone());

            let mut local_node = BlockchainState::new(Arc::clone(&chain_config_arc), storage);
            local_node.scan_genesis(chain_config_arc.genesis_block()).await.unwrap();

            let (alice_sk, alice_pk) =
                PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));

            // Create a funding transaction that creates `num_tx` outputs to be spent independently in mempool
            let mut tx1_builder = TransactionBuilder::new().add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            );

            let amount_per_output = Amount::from_atoms(1_000_000);
            for _ in 0..num_tx {
                tx1_builder = tx1_builder.add_output(TxOutput::Transfer(
                    OutputValue::Coin(amount_per_output),
                    alice_destination.clone(),
                ));
            }

            let signed_tx1 = tx1_builder.build();
            let tx1_id = signed_tx1.transaction().get_id();

            // Put the funding tx into a block and scan it
            let block_id = *tf
                .make_block_builder()
                .add_transaction(signed_tx1.clone())
                .build_and_process(&mut rng)
                .unwrap()
                .unwrap()
                .block_id();
            let block = tf.block(block_id);
            local_node.scan_blocks(BlockHeight::new(0), vec![block]).await.unwrap();

            let mut expected_txs = Vec::new();

            for i in 0..num_tx {
                let tx_out = TxOutput::Transfer(
                    OutputValue::Coin(amount_per_output),
                    alice_destination.clone(),
                );
                let prev_tx_out = signed_tx1.outputs()[i].clone();

                let transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(OutPointSourceId::Transaction(tx1_id), i as u32),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(tx_out.clone())
                    .build();

                let witness = InputWitness::Standard(
                    StandardInputSignature::produce_uniparty_signature_for_input(
                        &alice_sk,
                        SigHashType::all(),
                        alice_destination.clone(),
                        &transaction,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(&prev_tx_out))],
                        0,
                        &mut rng,
                    )
                    .unwrap(),
                );

                let signed_tx =
                    SignedTransaction::new(transaction.transaction().clone(), vec![witness])
                        .unwrap();

                // Add constructed transaction to the mempool
                local_node.add_mempool_tx(&signed_tx).await.unwrap();

                let transaction_id = signed_tx.transaction().get_id();
                let utxos = vec![Some(prev_tx_out)];

                let tx_json = json!({
                    "id": transaction_id.to_hash().encode_hex::<String>(),
                    "version_byte": signed_tx.transaction().version_byte(),
                    "is_replaceable": signed_tx.transaction().is_replaceable(),
                    "flags": signed_tx.transaction().flags(),
                    "inputs": signed_tx.transaction().inputs().iter().zip(utxos).map(|(inp, utxo)| json!({
                        "input": tx_input_to_json(inp, &TokenDecimals::Single(None), &chain_config),
                        "utxo": utxo.as_ref().map(|txo| txoutput_to_json(txo, &chain_config, &TokenDecimals::Single(None))),
                    })).collect::<Vec<_>>(),
                    "outputs": signed_tx.transaction().outputs()
                        .iter()
                        .map(|out| txoutput_to_json(out, &chain_config, &TokenDecimals::Single(None)))
                        .collect::<Vec<_>>(),
                });

                expected_txs.push(tx_json);
            }

            _ = tx.send(expected_txs);

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config: Arc::clone(&chain_config_arc),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((get_time(), vec![])),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, true).await
    });

    let expected_transactions_unordered = rx.await.unwrap();
    let num_tx = expected_transactions_unordered.len();

    // Query 1: Validate response contents independent of order logic via zero-offset fetch
    let url = format!("/api/v2/mempool/transaction?offset=0&items={num_tx}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("body: {}", body);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();

    assert_eq!(arr_body.len(), num_tx);

    // Reconstruct expected array to match dynamic server-side logic (BTreeMap key logic)
    let mut expected_transactions = Vec::new();
    for body_tx in arr_body {
        let expected_tx = expected_transactions_unordered
            .iter()
            .find(|tx| tx["id"] == body_tx["id"])
            .expect("Transaction not found in expected");
        compare_body(body_tx, expected_tx);
        expected_transactions.push(expected_tx.clone());
    }

    // Query 2: Validate list offset behaviors via subset extraction
    let mut rng = make_seedable_rng(seed);
    let offset = rng.gen_range(1..num_tx);
    let items = num_tx - offset;
    let url = format!("/api/v2/mempool/transaction?offset={offset}&items={items}");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("body: {}", body);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();

    assert_eq!(arr_body.len(), num_tx - offset);

    // Slice test matching precisely the server's list output boundaries
    for (expected_transaction, body_tx) in expected_transactions[offset..].iter().zip(arr_body) {
        compare_body(body_tx, expected_transaction);
    }

    task.abort();
}

#[track_caller]
fn compare_body(body: &Value, expected_transaction: &Value) {
    assert_eq!(body.get("id").unwrap(), &expected_transaction["id"]);
    assert_eq!(
        body.get("version_byte").unwrap(),
        &expected_transaction["version_byte"]
    );
    assert_eq!(
        body.get("is_replaceable").unwrap(),
        &expected_transaction["is_replaceable"]
    );
    assert_eq!(body.get("flags").unwrap(), &expected_transaction["flags"]);
    assert_eq!(body.get("inputs").unwrap(), &expected_transaction["inputs"]);
    assert_eq!(
        body.get("outputs").unwrap(),
        &expected_transaction["outputs"]
    );
}

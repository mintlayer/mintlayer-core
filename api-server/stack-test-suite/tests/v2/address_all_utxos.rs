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

use std::{borrow::Cow, collections::BTreeMap, sync::RwLock};

use api_web_server::{api::json_helpers::utxo_outpoint_to_json, CachedValues};
use common::{chain::UtxoOutPoint, primitives::time::get_time};

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_address() {
    let (task, response) = spawn_webserver("/api/v2/address/invalid-address/all-utxos").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid address");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn address_not_found(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = create_unit_test_config();

    let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));
    let address = Address::<Destination>::new(&chain_config, destination).unwrap();

    let (task, response) =
        spawn_webserver(&format!("/api/v2/address/{}/all-utxos", address.as_str())).await;

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let utxos = body.as_array().unwrap();

    assert!(utxos.is_empty());

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn multiple_utxos_to_single_address(#[case] seed: Seed) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<[(String, serde_json::Value); 2]>();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // generate addresses

                let (alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));
                let alice_address =
                    Address::<Destination>::new(&chain_config, alice_destination.clone()).unwrap();
                let mut alice_balance = Amount::from_atoms(1_000_000);
                let mut alice_utxos = BTreeMap::new();

                let (_bob_sk, bob_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));
                let bob_address =
                    Address::<Destination>::new(&chain_config, bob_destination.clone()).unwrap();
                let mut bob_utxos = BTreeMap::new();

                // setup initial transaction

                let previous_tx_out =
                    TxOutput::Transfer(OutputValue::Coin(alice_balance), alice_destination.clone());

                let transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(previous_tx_out.clone())
                    .build();

                let previous_transaction_id = transaction.transaction().get_id();

                let mut previous_witness = InputWitness::Standard(
                    StandardInputSignature::produce_uniparty_signature_for_input(
                        &alice_sk,
                        SigHashType::all(),
                        alice_destination.clone(),
                        &transaction,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(&previous_tx_out))],
                        0,
                        &mut rng,
                    )
                    .unwrap(),
                );

                let mut chainstate_block_ids = vec![*tf
                    .make_block_builder()
                    .add_transaction(transaction.clone())
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap()
                    .block_id()];

                // Generate two outputs for a single transaction

                let random_coin_amount1 = rng.gen_range(1..10);
                let random_coin_amount2 = rng.gen_range(1..10);

                alice_balance = (alice_balance - Amount::from_atoms(random_coin_amount1)).unwrap();
                alice_balance = (alice_balance - Amount::from_atoms(random_coin_amount2)).unwrap();

                let alice_tx_out =
                    TxOutput::Transfer(OutputValue::Coin(alice_balance), alice_destination.clone());

                let bob_tx_out1 = TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(random_coin_amount1)),
                    bob_destination.clone(),
                );

                let bob_tx_out2 = TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(random_coin_amount2)),
                    bob_destination.clone(),
                    OutputTimeLock::ForBlockCount(10),
                );

                let transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::Transaction(previous_transaction_id),
                            0,
                        ),
                        previous_witness.clone(),
                    )
                    .add_output(alice_tx_out.clone())
                    .add_output(bob_tx_out1.clone())
                    .add_output(bob_tx_out2.clone())
                    .build();

                let utxo = UtxoOutPoint::new(
                    OutPointSourceId::Transaction(transaction.transaction().get_id()),
                    0,
                );
                alice_utxos.insert(utxo, alice_tx_out);
                bob_utxos.insert(
                    UtxoOutPoint::new(
                        OutPointSourceId::Transaction(transaction.transaction().get_id()),
                        1,
                    ),
                    bob_tx_out1,
                );
                bob_utxos.insert(
                    UtxoOutPoint::new(
                        OutPointSourceId::Transaction(transaction.transaction().get_id()),
                        2,
                    ),
                    bob_tx_out2,
                );

                previous_witness = InputWitness::Standard(
                    StandardInputSignature::produce_uniparty_signature_for_input(
                        &alice_sk,
                        SigHashType::all(),
                        alice_destination.clone(),
                        &transaction,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(&previous_tx_out))],
                        0,
                        &mut rng,
                    )
                    .unwrap(),
                );

                let signed_transaction = SignedTransaction::new(
                    transaction.transaction().clone(),
                    vec![previous_witness.clone()],
                )
                .unwrap();

                chainstate_block_ids.push(
                    *tf.make_block_builder()
                        .add_transaction(signed_transaction)
                        .build_and_process(&mut rng)
                        .unwrap()
                        .unwrap()
                        .block_id(),
                );

                _ = tx.send([
                    (
                        alice_address.as_str().to_string(),
                        alice_utxos
                            .into_iter()
                            .map(|utxo| {
                                json!({
                                "outpoint": utxo_outpoint_to_json(&utxo.0),
                                "utxo": txoutput_to_json(&utxo.1, &chain_config, &TokenDecimals::Single(None))})
                            })
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                    (
                        bob_address.to_string(),
                        bob_utxos
                            .into_iter()
                            .map(|utxo| {
                                json!({
                                "outpoint": utxo_outpoint_to_json(&utxo.0),
                                "utxo": txoutput_to_json(&utxo.1, &chain_config, &TokenDecimals::Single(None))})
                            })
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                ]);

                chainstate_block_ids
                    .iter()
                    .map(|id| tf.block(tf.to_chain_block_id(id.into())))
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
    });

    for (address, expected) in rx.await.unwrap() {
        let url = format!("/api/v2/address/{address}/all-utxos");

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Failed getting address balance for {address}"
        );

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        eprintln!("asd\n\n");
        assert_eq!(body, expected);
    }

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<[(String, serde_json::Value); 2]>();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // generate addresses

                let (alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));
                let alice_address =
                    Address::<Destination>::new(&chain_config, alice_destination.clone()).unwrap();
                let mut alice_balance = Amount::from_atoms(1_000_000);
                let mut alice_utxos = BTreeMap::new();

                let (_bob_sk, bob_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));
                let bob_address =
                    Address::<Destination>::new(&chain_config, bob_destination.clone()).unwrap();
                let mut bob_utxos = BTreeMap::new();

                // setup initial transaction

                let mut previous_tx_out =
                    TxOutput::Transfer(OutputValue::Coin(alice_balance), alice_destination.clone());

                let transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(previous_tx_out.clone())
                    .build();

                let mut previous_transaction_id = transaction.transaction().get_id();

                let mut previous_witness = InputWitness::Standard(
                    StandardInputSignature::produce_uniparty_signature_for_input(
                        &alice_sk,
                        SigHashType::all(),
                        alice_destination.clone(),
                        &transaction,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(&previous_tx_out))],
                        0,
                        &mut rng,
                    )
                    .unwrap(),
                );

                let mut chainstate_block_ids = vec![*tf
                    .make_block_builder()
                    .add_transaction(transaction.clone())
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap()
                    .block_id()];

                for _ in 0..rng.gen_range(1..2) {
                    let random_coin_amount = rng.gen_range(1..10);

                    alice_balance =
                        (alice_balance - Amount::from_atoms(random_coin_amount * 2)).unwrap();

                    let alice_tx_out = TxOutput::Transfer(
                        OutputValue::Coin(alice_balance),
                        alice_destination.clone(),
                    );

                    let bob_tx_out = TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(random_coin_amount)),
                        bob_destination.clone(),
                    );
                    let bob_tx_out2 = TxOutput::LockThenTransfer(
                        OutputValue::Coin(Amount::from_atoms(random_coin_amount)),
                        bob_destination.clone(),
                        OutputTimeLock::ForBlockCount(rng.gen_range(1..100)),
                    );

                    let transaction = TransactionBuilder::new()
                        .add_input(
                            TxInput::from_utxo(
                                OutPointSourceId::Transaction(previous_transaction_id),
                                0,
                            ),
                            previous_witness.clone(),
                        )
                        .add_output(alice_tx_out.clone())
                        .add_output(bob_tx_out.clone())
                        .add_output(bob_tx_out2.clone())
                        .build();

                    alice_utxos.insert(
                        UtxoOutPoint::new(
                            OutPointSourceId::Transaction(transaction.transaction().get_id()),
                            0,
                        ),
                        alice_tx_out.clone(),
                    );
                    bob_utxos.insert(
                        UtxoOutPoint::new(
                            OutPointSourceId::Transaction(transaction.transaction().get_id()),
                            1,
                        ),
                        bob_tx_out,
                    );
                    bob_utxos.insert(
                        UtxoOutPoint::new(
                            OutPointSourceId::Transaction(transaction.transaction().get_id()),
                            2,
                        ),
                        bob_tx_out2,
                    );
                    previous_transaction_id = transaction.transaction().get_id();

                    previous_witness = InputWitness::Standard(
                        StandardInputSignature::produce_uniparty_signature_for_input(
                            &alice_sk,
                            SigHashType::all(),
                            alice_destination.clone(),
                            &transaction,
                            &[SighashInputCommitment::Utxo(Cow::Borrowed(&previous_tx_out))],
                            0,
                            &mut rng,
                        )
                        .unwrap(),
                    );

                    let signed_transaction = SignedTransaction::new(
                        transaction.transaction().clone(),
                        vec![previous_witness.clone()],
                    )
                    .unwrap();

                    chainstate_block_ids.push(
                        *tf.make_block_builder()
                            .add_transaction(signed_transaction)
                            .build_and_process(&mut rng)
                            .unwrap()
                            .unwrap()
                            .block_id(),
                    );

                    previous_tx_out = alice_tx_out;
                }

                _ = tx.send([
                    (
                        alice_address.as_str().to_string(),
                        alice_utxos
                            .into_iter()
                            .map(|utxo| {
                                json!({
                                "outpoint": utxo_outpoint_to_json(&utxo.0),
                                "utxo": txoutput_to_json(&utxo.1, &chain_config, &TokenDecimals::Single(None))})
                            })
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                    (
                        bob_address.to_string(),
                        bob_utxos
                            .into_iter()
                            .map(|utxo| {
                                json!({
                                "outpoint": utxo_outpoint_to_json(&utxo.0),
                                "utxo": txoutput_to_json(&utxo.1, &chain_config, &TokenDecimals::Single(None))})
                            })
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                ]);

                chainstate_block_ids
                    .iter()
                    .map(|id| tf.block(tf.to_chain_block_id(id.into())))
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
    });

    for (address, expected_values) in rx.await.unwrap() {
        let url = format!("/api/v2/address/{address}/all-utxos");

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Failed getting address balance for {address}"
        );

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body, expected_values);
    }

    task.abort();
}

// TODO test address balances after a reorg

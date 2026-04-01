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

use std::{borrow::Cow, sync::RwLock};

use api_web_server::{api::json_helpers::amount_to_json, CachedValues};
use common::primitives::time::get_time;

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_address() {
    let (task, response) = spawn_webserver("/api/v2/mempool/address/invalid-address").await;

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
        spawn_webserver(&format!("/api/v2/mempool/address/{}", address.as_str())).await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Address not found");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn multiple_outputs_to_single_address(#[case] seed: Seed) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let chain_config = create_unit_test_config();

            let transactions = {
                let tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // generate addresses

                let (alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));
                let alice_address =
                    Address::<Destination>::new(&chain_config, alice_destination.clone()).unwrap();
                let mut alice_balance = Amount::from_atoms(1_000_000);
                let mut alice_transaction_history: Vec<Id<Transaction>> = vec![];

                let (_bob_sk, bob_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));
                let bob_address =
                    Address::<Destination>::new(&chain_config, bob_destination.clone()).unwrap();
                let mut bob_balance = Amount::ZERO;
                let mut bob_locked_balance = Amount::ZERO;
                let mut bob_transaction_history: Vec<Id<Transaction>> = vec![];

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

                alice_transaction_history.push(transaction.transaction().get_id());
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

                // Generate two outputs for a single transaction

                let random_coin_amount1 = rng.gen_range(1..10);
                let random_coin_amount2 = rng.gen_range(1..10);
                let random_coin_amount3 = rng.gen_range(1..10);

                alice_balance = (alice_balance - Amount::from_atoms(random_coin_amount1)).unwrap();
                alice_balance = (alice_balance - Amount::from_atoms(random_coin_amount2)).unwrap();
                alice_balance = (alice_balance - Amount::from_atoms(random_coin_amount3)).unwrap();

                bob_balance = (bob_balance + Amount::from_atoms(random_coin_amount1)).unwrap();
                bob_balance = (bob_balance + Amount::from_atoms(random_coin_amount2)).unwrap();
                bob_locked_balance =
                    (bob_locked_balance + Amount::from_atoms(random_coin_amount3)).unwrap();

                let alice_tx_out =
                    TxOutput::Transfer(OutputValue::Coin(alice_balance), alice_destination.clone());

                let bob_tx_out1 = TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(random_coin_amount1)),
                    bob_destination.clone(),
                );

                let bob_tx_out2 = TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(random_coin_amount2)),
                    bob_destination.clone(),
                );

                let bob_tx_out3 = TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(random_coin_amount3)),
                    bob_destination.clone(),
                    OutputTimeLock::ForBlockCount(10),
                );

                let transaction2 = TransactionBuilder::new()
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
                    .add_output(bob_tx_out3.clone())
                    .build();

                alice_transaction_history.push(transaction2.transaction().get_id());
                bob_transaction_history.push(transaction2.transaction().get_id());

                previous_witness = InputWitness::Standard(
                    StandardInputSignature::produce_uniparty_signature_for_input(
                        &alice_sk,
                        SigHashType::all(),
                        alice_destination.clone(),
                        &transaction2,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(&previous_tx_out))],
                        0,
                        &mut rng,
                    )
                    .unwrap(),
                );

                let signed_transaction2 = SignedTransaction::new(
                    transaction2.transaction().clone(),
                    vec![previous_witness.clone()],
                )
                .unwrap();

                alice_transaction_history.sort();
                bob_transaction_history.sort();

                _ = tx.send([
                    (
                        alice_address.as_str().to_string(),
                        json!({
                            "coin_balance": amount_to_json(alice_balance, chain_config.coin_decimals()),
                            "locked_coin_balance": amount_to_json(Amount::ZERO, chain_config.coin_decimals()),
                            "transaction_history": alice_transaction_history,
                            "tokens": [],
                        }),
                    ),
                    (
                        bob_address.to_string(),
                        json!({
                            "coin_balance": amount_to_json(bob_balance, chain_config.coin_decimals()),
                            "locked_coin_balance": amount_to_json(bob_locked_balance, chain_config.coin_decimals()),
                            "transaction_history": bob_transaction_history,
                            "tokens": [],
                        }),
                    ),
                ]);

                [transaction, signed_transaction2]
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
            for tx in transactions {
                local_node.add_mempool_tx(&tx).await.unwrap();
            }

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

    for (address, expected_balance) in rx.await.unwrap() {
        let url = format!("/api/v2/mempool/address/{address}");

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

        assert_eq!(body, expected_balance);
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

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let chain_config = create_unit_test_config();

            let transactions = {
                let tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // generate addresses

                let (alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));
                let alice_address =
                    Address::<Destination>::new(&chain_config, alice_destination.clone()).unwrap();
                let mut alice_balance = Amount::from_atoms(1_000_000);
                let mut alice_transaction_history: Vec<Id<Transaction>> = vec![];

                let (_bob_sk, bob_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));
                let bob_address =
                    Address::<Destination>::new(&chain_config, bob_destination.clone()).unwrap();
                let mut bob_balance = Amount::ZERO;
                let mut bob_transaction_history: Vec<Id<Transaction>> = vec![];

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

                alice_transaction_history.push(transaction.transaction().get_id());
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

                let mut transactions = vec![transaction.clone()];

                for _ in 0..rng.gen_range(1..100) {
                    let random_coin_amount = rng.gen_range(1..10);

                    alice_balance =
                        (alice_balance - Amount::from_atoms(random_coin_amount)).unwrap();

                    bob_balance = (bob_balance + Amount::from_atoms(random_coin_amount)).unwrap();

                    let alice_tx_out = TxOutput::Transfer(
                        OutputValue::Coin(alice_balance),
                        alice_destination.clone(),
                    );

                    let bob_tx_out = TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(random_coin_amount)),
                        bob_destination.clone(),
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
                        .build();

                    alice_transaction_history.push(transaction.transaction().get_id());
                    bob_transaction_history.push(transaction.transaction().get_id());
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

                    transactions.push(signed_transaction.clone());

                    previous_tx_out = alice_tx_out;
                }

                alice_transaction_history.sort();
                bob_transaction_history.sort();

                _ = tx.send([
                    (
                        alice_address.as_str().to_string(),
                        json!({
                            "coin_balance": amount_to_json(alice_balance, chain_config.coin_decimals()),
                            "locked_coin_balance": amount_to_json(Amount::ZERO, chain_config.coin_decimals()),
                            "transaction_history": alice_transaction_history,
                            "tokens": [],
                        }),
                    ),
                    (
                        bob_address.to_string(),
                        json!({
                            "coin_balance": amount_to_json(bob_balance, chain_config.coin_decimals()),
                            "locked_coin_balance": amount_to_json(Amount::ZERO, chain_config.coin_decimals()),
                            "transaction_history": bob_transaction_history,
                            "tokens": [],
                        }),
                    ),
                ]);

                transactions
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
            for tx in transactions {
                local_node.add_mempool_tx(&tx).await.unwrap();
            }

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
        let url = format!("/api/v2/mempool/address/{address}");

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

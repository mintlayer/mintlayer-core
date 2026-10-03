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

use std::borrow::Cow;

use api_web_server::api::json_helpers::amount_to_json;
use common::{
    chain::{
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, UtxoOutPoint,
        config::emission_schedule::DEFAULT_INITIAL_MINT,
        make_token_id,
        tokens::{IsTokenFreezable, TokenId, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
    },
    primitives::H256,
};

use crate::DummyRPC;

use super::{
    helpers::{prepare_delegation, prepare_stake_pool, stake_delegation},
    *,
};

#[tokio::test]
async fn invalid_token_id() {
    let (task, response) = spawn_webserver("/api/v2/statistics/token/invalid-token-id").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid token Id");

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn token_not_found(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = create_unit_test_config();

    let token_id = TokenId::new(H256::random_using(&mut rng));
    let token_id = Address::<TokenId>::new(&chain_config, token_id).unwrap();

    let (task, response) =
        spawn_webserver(&format!("/api/v2/statistics/token/{}", token_id.as_str())).await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Token not found");

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok_tokens(#[case] seed: Seed) {
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

                // generate addresses

                let (alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));

                let token_decimals = rng.random_range(1..18);
                let token_issuance = TokenIssuanceV1 {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    number_of_decimals: token_decimals,
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                    total_supply: TokenTotalSupply::Unlimited,
                    authority: alice_destination.clone(),
                    is_freezable: IsTokenFreezable::No,
                };

                let issue_token_transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(
                            (Amount::from_atoms(100)
                                + chain_config.token_supply_change_fee(BlockHeight::zero()))
                            .unwrap(),
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                        token_issuance.clone(),
                    ))))
                    .build();

                let token_id = make_token_id(
                    &chain_config,
                    tf.next_block_height(),
                    issue_token_transaction.inputs(),
                )
                .unwrap();
                let to_mint = Amount::from_atoms(1000);
                let mint_transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::Transaction(
                                issue_token_transaction.transaction().get_id(),
                            ),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::MintTokens(token_id, to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(10)),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build();

                let token_witness = InputWitness::Standard(
                    StandardInputSignature::produce_uniparty_signature_for_input(
                        &alice_sk,
                        SigHashType::all(),
                        alice_destination.clone(),
                        &mint_transaction,
                        &[
                            SighashInputCommitment::Utxo(Cow::Borrowed(
                                &issue_token_transaction.outputs()[0],
                            )),
                            SighashInputCommitment::None,
                        ],
                        1,
                        &mut rng,
                    )
                    .unwrap(),
                );

                let signed_mint_tx = SignedTransaction::new(
                    mint_transaction.transaction().clone(),
                    vec![InputWitness::NoSignature(None), token_witness.clone()],
                )
                .unwrap();

                let to_burn = Amount::from_atoms(100);
                let unmint_transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::Transaction(mint_transaction.transaction().get_id()),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::Transaction(mint_transaction.transaction().get_id()),
                            1,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(token_id, to_burn)))
                    .build();

                let chainstate_block_ids = [*tf
                    .make_block_builder()
                    .add_transaction(issue_token_transaction.clone())
                    .add_transaction(signed_mint_tx.clone())
                    .add_transaction(unmint_transaction.clone())
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap()
                    .block_id()];

                _ = tx.send([(
                    token_id,
                    json!({
                    "circulating_supply": amount_to_json((to_mint - to_burn).unwrap(), token_decimals),
                    "preminted": amount_to_json(Amount::ZERO, token_decimals),
                    "staked": amount_to_json(Amount::ZERO, token_decimals),
                    "burned": amount_to_json(to_burn, token_decimals),
                                }),
                )]);

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
                stream_events: Default::default(),
            }
        };

        web_server(listener, web_server_state, false).await
    });

    let chain_config = create_unit_test_config();
    for (token_id, expected_values) in rx.await.unwrap() {
        let token_id = Address::new(&chain_config, token_id).unwrap();
        let url = format!("/api/v2/statistics/token/{token_id}");

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Failed getting token for {token_id}"
        );

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body, expected_values);
    }

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok_coins(#[case] seed: Seed) {
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

                let stake_pool_outpoint = UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );

                let mut available_amount = ((chain_config.min_stake_pool_pledge() * 10).unwrap()
                    + Amount::from_atoms(10000))
                .unwrap();

                let (transfer_outpoint, stake_pool_data, pool_id, _) = prepare_stake_pool(
                    stake_pool_outpoint,
                    &mut rng,
                    &mut available_amount,
                    &mut tf,
                );

                let (delegation_id, _, transfer_outpoint, _) = prepare_delegation(
                    transfer_outpoint,
                    &mut rng,
                    pool_id,
                    available_amount,
                    Some(Destination::AnyoneCanSpend),
                    &mut tf,
                );

                let (delegated_amount, transfer_outpoint, _) = stake_delegation(
                    &mut rng,
                    available_amount,
                    transfer_outpoint,
                    delegation_id,
                    &mut tf,
                );
                available_amount = (available_amount - delegated_amount).unwrap();

                let amount_to_unstake =
                    Amount::from_atoms(rng.random_range(1..=delegated_amount.into_atoms()));
                let amount_to_burn =
                    Amount::from_atoms(rng.random_range(1..=available_amount.into_atoms()));

                let undelegate_and_burn = TransactionBuilder::new()
                    .add_input(transfer_outpoint.into(), InputWitness::NoSignature(None))
                    .add_input(
                        TxInput::Account(AccountOutPoint::new(
                            AccountNonce::new(0),
                            AccountSpending::DelegationBalance(delegation_id, amount_to_unstake),
                        )),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(amount_to_burn)))
                    .build();

                tf.block_id(1);
                tf.block_id(2);
                tf.block_id(3);
                let block4 = tf
                    .make_block_builder()
                    .add_transaction(undelegate_and_burn.clone())
                    .build(&mut rng);
                tf.process_block(block4.clone(), BlockSource::Local).unwrap();

                let total_amount = (DEFAULT_INITIAL_MINT - amount_to_burn).unwrap();
                let staked = ((stake_pool_data.pledge() + delegated_amount).unwrap()
                    - amount_to_unstake)
                    .unwrap();

                let decimals = chain_config.coin_decimals();
                _ = tx.send([json!({
                "circulating_supply": amount_to_json(total_amount, decimals),
                "preminted": amount_to_json(DEFAULT_INITIAL_MINT, decimals),
                "staked": amount_to_json(staked, decimals),
                "burned": amount_to_json(amount_to_burn, decimals),
                            })]);

                // chainstate_block_ids
                tf.block_indexes
                    .iter()
                    .map(|idx| tf.block(tf.to_chain_block_id(idx.block_id().into())))
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
                stream_events: Default::default(),
            }
        };

        web_server(listener, web_server_state, false).await
    });

    for expected_values in rx.await.unwrap() {
        let url = "/api/v2/statistics/coin";

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Failed getting coin statistics");

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body, expected_values);
    }

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn coin_holders(#[case] seed: Seed) {
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

                let (_, alice_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                let (_, bob_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));
                let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));

                let transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(100)),
                        alice_destination.clone(),
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(50)),
                        bob_destination.clone(),
                    ))
                    .build();

                let block = tf.make_block_builder().add_transaction(transaction).build(&mut rng);
                tf.process_block(block.clone(), BlockSource::Local).unwrap();

                let alice_address = Address::new(&chain_config, alice_destination).unwrap();
                let bob_address = Address::new(&chain_config, bob_destination).unwrap();
                _ = tx.send((
                    alice_address.clone(),
                    bob_address.clone(),
                    chain_config.coin_decimals(),
                ));

                (alice_address, bob_address, vec![block])
            };
            let (_alice_address, _bob_address, chainstate_blocks) = chainstate_blocks;

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
                stream_events: Default::default(),
            }
        };

        web_server(listener, web_server_state, false).await
    });

    let (alice_address, bob_address, coin_decimals) = rx.await.unwrap();
    let alice_atoms = amount_to_json(Amount::from_atoms(100), coin_decimals);
    let bob_atoms = amount_to_json(Amount::from_atoms(50), coin_decimals);

    // the holder count is known from an unpaged request; the walk below is
    // bounded by it so a self-referencing cursor fails instead of hanging
    let response = reqwest::get(format!(
        "http://{}:{}/api/v2/statistics/coin/holders?items=100",
        addr.ip(),
        addr.port()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    let num_holders = body["items"].as_array().unwrap().len();
    assert!(num_holders >= 2);
    // the baseline is fetched with the server's maximum page size; a larger list
    // would be silently truncated and the bound below would be wrong
    assert!(num_holders < 100);

    // walk the whole holders list, one item per request
    let mut url = "/api/v2/statistics/coin/holders?items=1".to_owned();
    let mut holders = BTreeMap::<String, serde_json::Value>::new();
    let mut prev_amount: Option<String> = None;
    loop {
        // bounded by the known holder count so a self-referencing cursor fails
        // instead of hanging
        assert!(
            holders.len() < num_holders,
            "the holders cursor walk exceeded the expected number of holders"
        );
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "Failed getting coin holders");

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);

        let address = items[0]["address"].as_str().unwrap().to_owned();
        assert!(!holders.contains_key(&address), "duplicate holder address");
        let amount = items[0]["amount"]["atoms"].as_str().unwrap().to_owned();

        // the amounts are ordered, from the biggest to the smallest
        if let Some(prev) = prev_amount.replace(amount.clone()) {
            let (prev, amount) = (
                prev.parse::<u128>().unwrap(),
                amount.parse::<u128>().unwrap(),
            );
            assert!(prev >= amount);
        }
        holders.insert(address, items[0]["amount"].clone());

        match body["next_cursor"].as_str() {
            Some(cursor) => {
                url = format!("/api/v2/statistics/coin/holders?items=1&cursor={cursor}");
            }
            None => break,
        }
    }

    assert_eq!(holders.len(), num_holders);
    assert_eq!(holders.get(alice_address.as_str()), Some(&alice_atoms));
    assert_eq!(holders.get(bob_address.as_str()), Some(&bob_atoms));

    // an unknown token has no holders
    let mut rng = make_seedable_rng(seed);
    let token_id = TokenId::new(H256::random_using(&mut rng));
    let token_id = Address::<TokenId>::new(&create_unit_test_config(), token_id).unwrap();
    let response = reqwest::get(format!(
        "http://{}:{}/api/v2/statistics/token/{}/holders",
        addr.ip(),
        addr.port(),
        token_id.as_str()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 404);
    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "Token not found");

    // an invalid cursor is rejected
    let response = reqwest::get(format!(
        "http://{}:{}/api/v2/statistics/coin/holders?cursor=garbage",
        addr.ip(),
        addr.port()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "Invalid cursor");

    shutdown_task(task).await;
}

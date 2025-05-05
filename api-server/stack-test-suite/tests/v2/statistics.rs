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

use api_web_server::api::json_helpers::amount_to_json;
use common::{
    chain::{
        config::emission_schedule::DEFAULT_INITIAL_MINT,
        make_token_id,
        tokens::{IsTokenFreezable, TokenId, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, UtxoOutPoint,
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

    task.abort();
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

    task.abort();
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

                let token_decimals = rng.gen_range(1..18);
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
                        &[Some(&issue_token_transaction.outputs()[0]), None],
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

    task.abort();
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
                    Amount::from_atoms(rng.gen_range(1..=delegated_amount.into_atoms()));
                let amount_to_burn =
                    Amount::from_atoms(rng.gen_range(1..=available_amount.into_atoms()));

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

    task.abort();
}

// Copyright (c) 2024 RBB S.r.l
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

use common::chain::{
    AccountCommand, AccountNonce, UtxoOutPoint, make_token_id,
    tokens::{IsTokenFreezable, NftIssuance, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
};

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_offset() {
    let (task, response) = spawn_webserver("/api/v2/token?offset=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset");

    task.abort();
}

#[tokio::test]
async fn invalid_num_items() {
    let (task, response) = spawn_webserver("/api/v2/token?items=asd").await;

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
    let more_than_max = rng.random_range(101..1000);
    let (task, response) = spawn_webserver(&format!("/api/v2/token?items={more_than_max}")).await;

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
            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // generate addresses

                let (_, alice_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));

                let token_issuance = TokenIssuanceV1 {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    number_of_decimals: rng.random_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                    total_supply: TokenTotalSupply::Unlimited,
                    authority: alice_destination.clone(),
                    is_freezable: IsTokenFreezable::No,
                };

                let mut remaining = ((chain_config.fungible_token_issuance_fee() * 10).unwrap()
                    + (chain_config.nft_issuance_fee(BlockHeight::new(1)) * 10).unwrap())
                .unwrap();

                let mut token_ids = vec![];
                let mut input = TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );
                for _ in 0..10 {
                    let transaction = TransactionBuilder::new()
                        .add_input(input, InputWitness::NoSignature(None))
                        .add_output(TxOutput::Transfer(
                            OutputValue::Coin(remaining),
                            Destination::AnyoneCanSpend,
                        ))
                        .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                            token_issuance.clone(),
                        ))))
                        .build();

                    let token_id =
                        make_token_id(&chain_config, tf.next_block_height(), transaction.inputs())
                            .unwrap();
                    token_ids.push(token_id);
                    input = TxInput::from_utxo(
                        OutPointSourceId::Transaction(transaction.transaction().get_id()),
                        0,
                    );
                    remaining = (remaining - chain_config.fungible_token_issuance_fee()).unwrap();

                    tf.make_block_builder()
                        .add_transaction(transaction.clone())
                        .build_and_process(&mut rng)
                        .unwrap()
                        .unwrap();
                }

                let mut nft_ids = vec![];
                for _ in 0..10 {
                    let nft = test_utils::token_utils::random_nft_issuance(&chain_config, &mut rng);
                    let token_id =
                        make_token_id(&chain_config, tf.next_block_height(), &[input.clone()])
                            .unwrap();

                    // issue NFT
                    let transaction = TransactionBuilder::new()
                        .add_input(input, InputWitness::NoSignature(None))
                        .add_output(TxOutput::Transfer(
                            OutputValue::Coin(remaining),
                            Destination::AnyoneCanSpend,
                        ))
                        .add_output(TxOutput::IssueNft(
                            token_id,
                            Box::new(NftIssuance::V0(nft.clone())),
                            alice_destination.clone(),
                        ))
                        .build();

                    let token_id =
                        make_token_id(&chain_config, tf.next_block_height(), transaction.inputs())
                            .unwrap();
                    nft_ids.push(token_id);
                    input = TxInput::from_utxo(
                        OutPointSourceId::Transaction(transaction.transaction().get_id()),
                        0,
                    );
                    remaining =
                        (remaining - chain_config.nft_issuance_fee(BlockHeight::new(1))).unwrap();

                    tf.make_block_builder()
                        .add_transaction(transaction.clone())
                        .build_and_process(&mut rng)
                        .unwrap()
                        .unwrap();
                }

                _ = tx.send([(token_ids, nft_ids)]);

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

    let chain_config = create_unit_test_config();
    for (token_ids, nft_ids) in rx.await.unwrap() {
        let url = format!(
            "/api/v2/token?offset=0&items={}",
            token_ids.len() + nft_ids.len()
        );

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Failed getting token ids");

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr_body = body.as_array().unwrap();

        for token_id in token_ids {
            assert!(arr_body.contains(&serde_json::Value::String(
                Address::new(&chain_config, token_id).unwrap().into_string()
            )));
        }

        for token_id in nft_ids {
            assert!(arr_body.contains(&serde_json::Value::String(
                Address::new(&chain_config, token_id).unwrap().into_string()
            )));
        }
    }

    task.abort();
}

// Tokens with multiple state changes must appear only once in the response (issue #1982)
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn no_duplicate_ids_for_tokens_with_state_changes(#[case] seed: Seed) {
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

                // AnyoneCanSpend authority so the mint input can go unsigned
                let token_issuance = TokenIssuanceV1 {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    number_of_decimals: rng.random_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                    total_supply: TokenTotalSupply::Unlimited,
                    authority: Destination::AnyoneCanSpend,
                    is_freezable: IsTokenFreezable::No,
                };

                let genesis_outpoint = UtxoOutPoint::new(tf.best_block_id().into(), 0);
                let genesis_coins = chainstate_test_framework::get_output_value(
                    tf.chainstate.utxo(&genesis_outpoint).unwrap().unwrap().output(),
                )
                .unwrap()
                .coin_amount()
                .unwrap();

                let issuance_fee = chain_config.fungible_token_issuance_fee();
                let supply_change_fee = chain_config.token_supply_change_fee(BlockHeight::zero());

                // issue a token
                let coins_after_issue = (genesis_coins - issuance_fee).unwrap();
                let issue_tx = TransactionBuilder::new()
                    .add_input(genesis_outpoint.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(coins_after_issue),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                        token_issuance.clone(),
                    ))))
                    .build();
                let minted_token_id =
                    make_token_id(&chain_config, tf.next_block_height(), issue_tx.inputs())
                        .unwrap();
                let issue_tx_id = issue_tx.transaction().get_id();
                tf.make_block_builder()
                    .add_transaction(issue_tx)
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap();

                // mint it, giving the token a second state row
                let amount_to_mint = Amount::from_atoms(rng.random_range(100..1000));
                let coins_after_mint = (coins_after_issue - supply_change_fee).unwrap();
                let mint_tx = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::MintTokens(minted_token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(issue_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(coins_after_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(minted_token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build();
                let mint_tx_id = mint_tx.transaction().get_id();
                tf.make_block_builder()
                    .add_transaction(mint_tx)
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap();

                // issue a second token with a single state row and the same ticker
                let coins_after_second_issue = (coins_after_mint - issuance_fee).unwrap();
                let second_issue_tx = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(coins_after_second_issue),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                        token_issuance,
                    ))))
                    .build();
                let single_row_token_id = make_token_id(
                    &chain_config,
                    tf.next_block_height(),
                    second_issue_tx.inputs(),
                )
                .unwrap();
                tf.make_block_builder()
                    .add_transaction(second_issue_tx)
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap();

                _ = tx.send((minted_token_id, single_row_token_id));

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

    let chain_config = create_unit_test_config();
    let (minted_token_id, single_row_token_id) = rx.await.unwrap();
    let minted_token_address = Address::new(&chain_config, minted_token_id).unwrap().into_string();
    let single_row_token_address =
        Address::new(&chain_config, single_row_token_id).unwrap().into_string();

    for url in [
        "/api/v2/token?offset=0&items=10".to_string(),
        "/api/v2/token/ticker/XXXX?offset=0&items=10".to_string(),
    ] {
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Failed getting token ids");

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let ids = body.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>();

        assert_eq!(
            ids.iter().filter(|id| **id == minted_token_address).count(),
            1
        );
        assert_eq!(
            ids.iter().filter(|id| **id == single_row_token_address).count(),
            1
        );

        let unique_ids = ids.iter().copied().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique_ids.len(), ids.len(), "duplicate token ids: {ids:?}");
    }

    task.abort();
}

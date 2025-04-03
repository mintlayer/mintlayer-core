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

use common::chain::{make_order_id, OrderAccountCommand, OrderData};

use super::*;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn create_fill_conclude_order(#[case] seed: Seed) {
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

                // Issue and mint some tokens to create an order with different currencies
                let issue_and_mint_result =
                    helpers::issue_and_mint_tokens_from_genesis(&mut rng, &mut tf);

                // Create order
                let order_data = OrderData::new(
                    Destination::AnyoneCanSpend,
                    OutputValue::Coin(Amount::from_atoms(10)),
                    OutputValue::TokenV1(issue_and_mint_result.token_id, Amount::from_atoms(10)),
                );
                let order_id = make_order_id(&issue_and_mint_result.tokens_outpoint);
                let tx_1 = TransactionBuilder::new()
                    .add_input(
                        TxInput::Utxo(issue_and_mint_result.tokens_outpoint),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                    .build();
                let tx_1_id = tx_1.transaction().get_id();

                let block1 = tf.make_block_builder().add_transaction(tx_1.clone()).build(&mut rng);
                tf.process_block(block1.clone(), BlockSource::Local).unwrap();

                // Fill order
                let tx2 = TransactionBuilder::new()
                    .add_input(
                        TxInput::Utxo(issue_and_mint_result.change_outpoint),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                            order_id,
                            Amount::from_atoms(1),
                            Destination::AnyoneCanSpend,
                        )),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(issue_and_mint_result.token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build();
                let tx_2_id = tx2.transaction().get_id();

                let block2 = tf.make_block_builder().add_transaction(tx2).build(&mut rng);
                tf.process_block(block2.clone(), BlockSource::Local).unwrap();

                // Conclude order
                let tx3 = TransactionBuilder::new()
                    .add_input(
                        TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id)),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(issue_and_mint_result.token_id, Amount::from_atoms(9)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build();
                let tx_3_id = tx3.transaction().get_id();

                let block3 = tf.make_block_builder().add_transaction(tx3).build(&mut rng);
                tf.process_block(block3.clone(), BlockSource::Local).unwrap();

                _ = tx.send((
                    block1.get_id().to_hash().encode_hex::<String>(),
                    tx_1_id.to_hash().encode_hex::<String>(),
                    block2.get_id().to_hash().encode_hex::<String>(),
                    tx_2_id.to_hash().encode_hex::<String>(),
                    block3.get_id().to_hash().encode_hex::<String>(),
                    tx_3_id.to_hash().encode_hex::<String>(),
                ));

                vec![
                    issue_and_mint_result.issue_block,
                    issue_and_mint_result.mint_block,
                    block1,
                    block2,
                    block3,
                ]
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

    let (block1_id, tx1_id, block2_id, tx2_id, block3_id, tx3_id) = rx.await.unwrap();

    let check_url = |url| async move {
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    };

    check_url(format!("/api/v2/block/{block1_id}")).await;
    check_url(format!("/api/v2/block/{block2_id}")).await;
    check_url(format!("/api/v2/block/{block3_id}")).await;

    check_url(format!("/api/v2/transaction/{tx1_id}")).await;
    check_url(format!("/api/v2/transaction/{tx2_id}")).await;
    check_url(format!("/api/v2/transaction/{tx3_id}")).await;

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn order_pairs(#[case] seed: Seed) {
    use common::{chain::tokens::TokenId, primitives::H256};

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

                // Issue and mint some tokens to create an order with different currencies
                let issue_and_mint_result =
                    helpers::issue_and_mint_tokens_from_genesis(&mut rng, &mut tf);

                // Create order
                let order_data = OrderData::new(
                    Destination::AnyoneCanSpend,
                    OutputValue::Coin(Amount::from_atoms(10)),
                    OutputValue::TokenV1(issue_and_mint_result.token_id, Amount::from_atoms(10)),
                );
                let order_id = make_order_id(&issue_and_mint_result.tokens_outpoint);
                let tx_1 = TransactionBuilder::new()
                    .add_input(
                        TxInput::Utxo(issue_and_mint_result.tokens_outpoint),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                    .build();

                let block1 = tf.make_block_builder().add_transaction(tx_1.clone()).build(&mut rng);
                tf.process_block(block1.clone(), BlockSource::Local).unwrap();

                _ = tx.send((
                    Address::new(&chain_config, order_id).unwrap().into_string(),
                    chain_config.coin_ticker().to_owned(),
                    Address::new(&chain_config, issue_and_mint_result.token_id)
                        .unwrap()
                        .into_string(),
                ));

                vec![issue_and_mint_result.issue_block, issue_and_mint_result.mint_block, block1]
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

    let (order_id, ml, tkn) = rx.await.unwrap();

    // ML_TKN
    {
        let url = format!("/api/v2/order/pair/{}_{}?offset=0&items={}", ml, tkn, 1);

        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr_body = body.as_array().unwrap();

        assert_eq!(arr_body.len(), 1);
        assert_eq!(
            arr_body[0].as_object().unwrap().get("order_id").unwrap(),
            &serde_json::Value::String(order_id.clone())
        );
    }

    // TKN_ML
    {
        let url = format!("/api/v2/order/pair/{}_{}?offset=0&items={}", tkn, ml, 1);

        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr_body = body.as_array().unwrap();

        assert_eq!(arr_body.len(), 1);
        assert_eq!(
            arr_body[0].as_object().unwrap().get("order_id").unwrap(),
            &serde_json::Value::String(order_id)
        );
    }

    let mut rng = make_seedable_rng(seed);

    // Random ticker
    let random_ticker = test_utils::random_ascii_alphanumeric_string(&mut rng, 3..5);
    let url = format!(
        "/api/v2/order/pair/{}_{}?offset=0&items={}",
        random_ticker, ml, 1
    );

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid token Id");

    // Random token
    let chain_config = create_unit_test_config();
    let random_token_id = TokenId::new(H256::random_using(&mut rng));
    let random_token_id = Address::new(&chain_config, random_token_id).unwrap().into_string();

    let url = format!(
        "/api/v2/order/pair/{}_{}?offset=0&items={}",
        random_token_id, ml, 1
    );

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();
    assert!(arr_body.is_empty());

    task.abort();
}

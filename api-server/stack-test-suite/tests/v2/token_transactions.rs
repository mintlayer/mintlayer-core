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

use serde_json::Value;

use chainstate_test_framework::empty_witness;
use common::{
    chain::{tokens::TokenId, AccountCommand, AccountNonce, UtxoOutPoint},
    primitives::H256,
};

use crate::v2::helpers::{issue_and_mint_tokens_from_genesis, IssueAndMintTokensResult};

use super::*;

#[tokio::test]
async fn invalid_token_id() {
    let (task, response) = spawn_webserver("/api/v2/token/invalid-token-id/transactions").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid token Id");

    task.abort();
}

#[tokio::test]
async fn invalid_offset() {
    let (task, response) = spawn_webserver("/api/v2/transaction?offset=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset");

    task.abort();
}

#[tokio::test]
async fn invalid_num_items() {
    let token_id = TokenId::new(H256::zero());
    let chain_config = create_unit_test_config();
    let token_id = Address::new(&chain_config, token_id).expect("no error").into_string();

    let (task, response) =
        spawn_webserver(&format!("/api/v2/token/{token_id}/transactions?items=asd")).await;

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

    let token_id = TokenId::new(H256::zero());
    let chain_config = create_unit_test_config();
    let token_id = Address::new(&chain_config, token_id).expect("no error").into_string();

    let (task, response) = spawn_webserver(&format!(
        "/api/v2/token/{token_id}/transactions?items={more_than_max}"
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
            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let genesis_outpoint = UtxoOutPoint::new(tf.best_block_id().into(), 0);
                let genesis_coins = chainstate_test_framework::get_output_value(
                    tf.chainstate.utxo(&genesis_outpoint).unwrap().unwrap().output(),
                )
                .unwrap()
                .coin_amount()
                .unwrap();

                let token_issuance_fee =
                    tf.chainstate.get_chain_config().fungible_token_issuance_fee();

                let min_amount_to_mint = Amount::from_atoms(100);
                let IssueAndMintTokensResult {
                    token_id,
                    issue_block,
                    mint_block,
                    change_outpoint,
                    tokens_outpoint,
                    minted_tokens,
                } = issue_and_mint_tokens_from_genesis(min_amount_to_mint, &mut rng, &mut tf);

                let coins_after_issue = (genesis_coins - token_issuance_fee).unwrap();

                // Issue token
                let issue_token_tx = &issue_block.transactions()[0];
                let issue_token_tx_id = issue_token_tx.transaction().get_id();

                // Mint tokens
                let token_supply_change_fee =
                    tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
                let coins_after_mint = (coins_after_issue - token_supply_change_fee).unwrap();

                let mint_tokens_tx = &mint_block.transactions()[0];
                let mint_tokens_tx_id = mint_tokens_tx.transaction().get_id();

                // Unmint tokens
                let coins_after_unmint = (coins_after_mint - token_supply_change_fee).unwrap();
                let tokens_to_unmint = Amount::from_atoms(1);
                let tokens_left_after_unmint = (minted_tokens - tokens_to_unmint).unwrap();
                let unmint_tokens_tx = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::UnmintTokens(token_id),
                        ),
                        empty_witness(&mut rng),
                    )
                    .add_input(TxInput::Utxo(change_outpoint), empty_witness(&mut rng))
                    .add_input(TxInput::Utxo(tokens_outpoint), empty_witness(&mut rng))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(coins_after_unmint),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, tokens_left_after_unmint),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        tokens_to_unmint,
                    )))
                    .build();
                let unmint_tokens_tx_id = unmint_tokens_tx.transaction().get_id();

                let block3 =
                    tf.make_block_builder().add_transaction(unmint_tokens_tx).build(&mut rng);

                tf.process_block(block3.clone(), chainstate::BlockSource::Local).unwrap();

                // Change token metadata uri
                let coins_after_change_token_authority =
                    (coins_after_unmint - token_supply_change_fee).unwrap();
                let change_token_authority_tx = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(2),
                            AccountCommand::ChangeTokenMetadataUri(
                                token_id,
                                "http://uri".as_bytes().to_vec(),
                            ),
                        ),
                        empty_witness(&mut rng),
                    )
                    .add_input(
                        TxInput::from_utxo(unmint_tokens_tx_id.into(), 0),
                        empty_witness(&mut rng),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(coins_after_change_token_authority),
                        Destination::AnyoneCanSpend,
                    ))
                    .build();
                let change_token_authority_tx_id = change_token_authority_tx.transaction().get_id();

                let block4 = tf
                    .make_block_builder()
                    .add_transaction(change_token_authority_tx)
                    .build(&mut rng);

                tf.process_block(block4.clone(), chainstate::BlockSource::Local).unwrap();

                let token_transactions = [
                    issue_token_tx_id,
                    mint_tokens_tx_id,
                    unmint_tokens_tx_id,
                    change_token_authority_tx_id,
                ];

                _ = tx.send((
                    Address::new(&chain_config, token_id).expect("no error").into_string(),
                    token_transactions,
                ));

                vec![issue_block, mint_block, block3, block4]
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

    let (token_id, expected_transactions) = rx.await.unwrap();
    let num_tx = expected_transactions.len();

    let url = format!("/api/v2/token/{token_id}/transactions?offset=999&items={num_tx}");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("body: {}", body);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();

    assert_eq!(arr_body.len(), num_tx);
    eprintln!("{expected_transactions:?}");
    for (tx_id, body) in expected_transactions.iter().rev().zip(arr_body) {
        compare_body(
            body,
            &json!({
                "tx_id": tx_id,
            }),
        );
    }

    let mut rng = make_seedable_rng(seed);
    let offset = rng.gen_range(1..num_tx);
    let items = num_tx - offset;

    let tx_global_index = &arr_body[offset - 1].get("tx_global_index").unwrap();
    eprintln!("tx_global_index: '{tx_global_index}'");
    let url =
        format!("/api/v2/token/{token_id}/transactions?offset={tx_global_index}&items={items}");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("body: {}", body);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr_body = body.as_array().unwrap();

    assert_eq!(arr_body.len(), num_tx - offset);
    for (tx_id, body) in expected_transactions.iter().rev().skip(offset).zip(arr_body) {
        compare_body(
            body,
            &json!({
                "tx_id": tx_id,
            }),
        );
    }

    task.abort();
}

#[track_caller]
fn compare_body(body: &Value, expected_transaction: &Value) {
    assert_eq!(body.get("tx_id").unwrap(), &expected_transaction["tx_id"]);
}

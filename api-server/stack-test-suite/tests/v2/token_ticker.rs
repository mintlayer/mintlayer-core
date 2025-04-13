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
    make_token_id,
    tokens::{IsTokenFreezable, NftIssuance, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
};

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_offset() {
    let (task, response) = spawn_webserver("/api/v2/token/ticker/XXXX?offset=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset");

    task.abort();
}

#[tokio::test]
async fn invalid_num_items() {
    let (task, response) = spawn_webserver("/api/v2/token/ticker/XXXX?items=asd").await;

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
    let (task, response) =
        spawn_webserver(&format!("/api/v2/token/ticker/XXXX?items={more_than_max}")).await;

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

    let token_ticker = "XXXX";
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
                    token_ticker: token_ticker.as_bytes().to_vec(),
                    number_of_decimals: rng.gen_range(1..18),
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
                        make_token_id(&chain_config, BlockHeight::zero(), transaction.inputs())
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
                    let mut nft =
                        test_utils::nft_utils::random_nft_issuance(&chain_config, &mut rng);
                    nft.metadata.ticker = token_ticker.as_bytes().to_vec();
                    let token_id =
                        make_token_id(&chain_config, BlockHeight::zero(), &[input.clone()])
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
                        make_token_id(&chain_config, BlockHeight::zero(), transaction.inputs())
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
            "/api/v2/token/ticker/{}?offset=0&items={}",
            token_ticker,
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

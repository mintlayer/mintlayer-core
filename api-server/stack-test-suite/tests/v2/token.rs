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

use api_server_common::storage::storage_api::FungibleTokenData;
use api_web_server::api::json_helpers::{amount_to_json, to_json_string};
use common::{
    chain::{
        make_token_id,
        tokens::{
            IsTokenFreezable, IsTokenFrozen, TokenId, TokenIssuance, TokenIssuanceV1,
            TokenTotalSupply,
        },
        AccountNonce,
    },
    primitives::H256,
};

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_token_id() {
    let (task, response) = spawn_webserver("/api/v2/token/invalid-token-id").await;

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

    let (task, response) = spawn_webserver(&format!("/api/v2/token/{}", token_id.as_str())).await;

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
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                    total_supply: TokenTotalSupply::Unlimited,
                    authority: alice_destination,
                    is_freezable: IsTokenFreezable::No,
                };

                let transaction = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                        token_issuance.clone(),
                    ))))
                    .build();

                let token_id =
                    make_token_id(&chain_config, tf.next_block_height(), transaction.inputs())
                        .unwrap();

                let chainstate_block_ids = [*tf
                    .make_block_builder()
                    .add_transaction(transaction.clone())
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap()
                    .block_id()];

                let token_data = FungibleTokenData {
                    token_ticker: token_issuance.token_ticker.clone(),
                    number_of_decimals: token_issuance.number_of_decimals,
                    metadata_uri: token_issuance.metadata_uri.clone(),
                    circulating_supply: Amount::ZERO,
                    total_supply: token_issuance.total_supply,
                    is_locked: false,
                    frozen: IsTokenFrozen::No(token_issuance.is_freezable),
                    authority: token_issuance.authority.clone(),
                    next_nonce: AccountNonce::new(0),
                };

                _ = tx.send([(
                    token_id,
                    json!({
                        "authority": Address::new(&chain_config, token_data.authority.clone()).expect(
                            "no error in encoding"
                        ).as_str(),
                        "is_locked": token_data.is_locked,
                        "circulating_supply": amount_to_json(token_data.circulating_supply, token_data.number_of_decimals),
                        "token_ticker": to_json_string(&token_data.token_ticker),
                        "metadata_uri": to_json_string(&token_data.metadata_uri),
                        "number_of_decimals": token_data.number_of_decimals,
                        "total_supply": token_data.total_supply,
                        "frozen": false,
                        "is_token_freezable": false,
                        "is_token_unfreezable": None::<bool>,
                        "next_nonce": token_data.next_nonce,
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
        let url = format!("/api/v2/token/{token_id}");

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

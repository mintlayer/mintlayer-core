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

use api_server_common::storage::storage_api::NftWithOwner;
use api_web_server::api::json_helpers::nft_with_owner_to_json;
use common::{
    chain::{
        make_token_id,
        tokens::{NftIssuance, TokenId},
    },
    primitives::H256,
};

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_nft_id() {
    let (task, response) = spawn_webserver("/api/v2/nft/invalid-token-id").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid NFT Id");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn nft_not_found(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = create_unit_test_config();

    let token_id = TokenId::new(H256::random_using(&mut rng));
    let token_id = Address::<TokenId>::new(&chain_config, token_id).unwrap();

    let (task, response) = spawn_webserver(&format!("/api/v2/nft/{}", token_id.as_str())).await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "NFT not found");

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

                let (alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));

                let nft = test_utils::token_utils::random_nft_issuance(&chain_config, &mut rng);

                let input = TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );

                let token_id =
                    make_token_id(&chain_config, tf.next_block_height(), &[input.clone()]).unwrap();

                // issue NFT
                let issue_nft_tx = TransactionBuilder::new()
                    .add_input(input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(NftIssuance::V0(nft.clone())),
                        alice_destination.clone(),
                    ))
                    .build();
                let issue_nft_tx_id = issue_nft_tx.transaction().get_id();

                // transfer NFT
                let transfer_nft_tx = {
                    let tx = TransactionBuilder::new()
                        .add_input(
                            TxInput::from_utxo(issue_nft_tx_id.into(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::Transfer(
                            OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                            alice_destination.clone(),
                        ))
                        .build();

                    let sig = InputWitness::Standard(
                        StandardInputSignature::produce_uniparty_signature_for_input(
                            &alice_sk,
                            SigHashType::all(),
                            alice_destination.clone(),
                            &tx,
                            &[SighashInputCommitment::Utxo(Cow::Borrowed(
                                &issue_nft_tx.outputs()[0],
                            ))],
                            0,
                            &mut rng,
                        )
                        .unwrap(),
                    );
                    SignedTransaction::new(tx.take_transaction(), vec![sig]).unwrap()
                };

                let chainstate_block_ids = [*tf
                    .make_block_builder()
                    .with_transactions(vec![issue_nft_tx, transfer_nft_tx])
                    .build_and_process(&mut rng)
                    .unwrap()
                    .unwrap()
                    .block_id()];

                _ = tx.send([(
                    token_id,
                    nft_with_owner_to_json(
                        &NftWithOwner {
                            nft: NftIssuance::V0(nft),
                            owner: Some(alice_destination),
                        },
                        &chain_config,
                    ),
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
        let url = format!("/api/v2/nft/{token_id}");

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Failed getting nft for {token_id}");

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body, expected_values);
    }

    task.abort();
}

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

use std::sync::RwLock;

use api_web_server::{api::json_helpers::amount_to_json, CachedValues};
use common::{
    chain::{AccountNonce, UtxoOutPoint},
    primitives::time::get_time,
};

use crate::DummyRPC;

use super::{
    helpers::{prepare_delegation, prepare_stake_pool, stake_delegation},
    *,
};

#[tokio::test]
async fn invalid_address() {
    let (task, response) = spawn_webserver("/api/v2/address/invalid-address/delegations").await;

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
        spawn_webserver(&format!("/api/v2/address/{}/delegations", address.as_str())).await;

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
async fn ok(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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

                let (_alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));
                let alice_address =
                    Address::<Destination>::new(&chain_config, alice_destination.clone()).unwrap();

                let (_bob_sk, bob_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));
                let bob_address =
                    Address::<Destination>::new(&chain_config, bob_destination).unwrap();

                let stake_pool_outpoint = UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );
                let mut available_amount = ((chain_config.min_stake_pool_pledge() * 10).unwrap()
                    + Amount::from_atoms(10000))
                .unwrap();

                let (transfer_outpoint, _stake_pool_data, pool_id, block) = prepare_stake_pool(
                    stake_pool_outpoint,
                    &mut rng,
                    &mut available_amount,
                    &mut tf,
                );

                let (_transfer_outpoint, mut delegations) = (0..rng.gen_range(0..5)).fold(
                    (transfer_outpoint, vec![]),
                    |(transfer_outpoint, mut delegations), _| {
                        if available_amount == Amount::ZERO {
                            return (transfer_outpoint, delegations);
                        }

                        let (delegation_id, dest, transfer_outpoint, block) = prepare_delegation(
                            transfer_outpoint,
                            &mut rng,
                            pool_id,
                            available_amount,
                            Some(alice_destination.clone()),
                            &mut tf,
                        );

                        let (amount, transfer_outpoint, block2) = stake_delegation(
                            &mut rng,
                            available_amount,
                            transfer_outpoint,
                            delegation_id,
                            &mut tf,
                        );
                        available_amount = (available_amount - amount).unwrap();

                        delegations.push((delegation_id, amount, dest, vec![block, block2]));
                        (transfer_outpoint, delegations)
                    },
                );

                let mut blocks = vec![];
                tf.process_block(block.clone(), BlockSource::Local).unwrap();
                blocks.push(block.clone());
                for delegation in &delegations {
                    for block in &delegation.3 {
                        tf.process_block(block.clone(), BlockSource::Local).unwrap();
                        blocks.push(block.clone());
                    }
                }

                delegations.sort_by_key(|(id, _, _, _)| *id);

                _ = tx.send([
                    (
                        alice_address.as_str().to_string(),
                        delegations
                            .into_iter()
                            .map(|(delegation_id, amount, _, _)| {
                                json!({
                                "delegation_id": Address::new(&chain_config, delegation_id).expect(
                                    "no error in encoding"
                                ).as_str(),
                                "pool_id": Address::new(&chain_config, pool_id).expect(
                                    "no error in encoding"
                                ).as_str(),
                                "next_nonce": AccountNonce::new(0),
                                "spend_destination": alice_address.as_str(),
                                "balance": amount_to_json(amount, chain_config.coin_decimals()),
                            })})
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                    (
                        bob_address.to_string(),
                        serde_json::Value::Array(vec![]),
                    ),
                ]);

                blocks
            };

            let storage = {
                let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                let mut db_tx = storage.transaction_rw().await.unwrap();
                db_tx.initialize_storage(&chain_config).await.unwrap();
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
        let url = format!("/api/v2/address/{address}/delegations");

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Failed getting address delegations for {address}"
        );

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(body, expected);
    }

    task.abort();
}

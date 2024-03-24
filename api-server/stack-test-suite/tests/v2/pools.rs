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

use std::cmp::Reverse;

use api_web_server::api::json_helpers::amount_to_json;
use common::chain::UtxoOutPoint;

use super::{
    helpers::{prepare_delegation, prepare_stake_pool, stake_delegation},
    *,
};

#[tokio::test]
async fn invalid_offset() {
    let (task, response) = spawn_webserver("/api/v2/pool?offset=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid offset");

    task.abort();
}

#[tokio::test]
async fn invalid_num_items() {
    let (task, response) = spawn_webserver("/api/v2/pool?items=asd").await;

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
    let (task, response) = spawn_webserver(&format!("/api/v2/pool?items={more_than_max}")).await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid number of items");

    task.abort();
}

#[tokio::test]
async fn invalid_sort_order() {
    let (task, response) = spawn_webserver("/api/v2/pool?sort=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid pools sort order");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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

                let (_, pools) = (0..rng.gen_range(1..5)).fold(
                    (stake_pool_outpoint, vec![]),
                    |(stake_pool_outpoint, mut pools), _| {
                        if available_amount == Amount::ZERO {
                            return (stake_pool_outpoint, pools);
                        }

                        let (transfer_outpoint, stake_pool_data, pool_id, block) =
                            prepare_stake_pool(
                                stake_pool_outpoint,
                                &mut rng,
                                &mut available_amount,
                                &mut tf,
                            );

                        let (transfer_outpoint, delegations) = (0..rng.gen_range(0..5)).fold(
                            (transfer_outpoint, vec![]),
                            |(transfer_outpoint, mut delegations), _| {
                                if available_amount == Amount::ZERO {
                                    return (transfer_outpoint, delegations);
                                }

                                let (delegation_id, dest, transfer_outpoint, block) =
                                    prepare_delegation(
                                        transfer_outpoint,
                                        &mut rng,
                                        pool_id,
                                        available_amount,
                                        None,
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

                                delegations.push((
                                    delegation_id,
                                    amount,
                                    dest,
                                    vec![block, block2],
                                ));
                                (transfer_outpoint, delegations)
                            },
                        );

                        pools.push((pool_id, stake_pool_data, delegations, block));

                        (transfer_outpoint, pools)
                    },
                );

                let mut blocks = vec![];
                for pool in &pools {
                    tf.process_block(pool.3.clone(), BlockSource::Local).unwrap();
                    blocks.push(pool.3.clone());
                    for delegation in &pool.2 {
                        for block in &delegation.3 {
                            tf.process_block(block.clone(), BlockSource::Local).unwrap();
                            blocks.push(block.clone());
                        }
                    }
                }

                _ = tx.send(pools);

                blocks
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
    let mut pools = rx.await.unwrap();

    {
        pools.reverse();
        let items = pools.len();
        let url = format!("/api/v2/pool?sort=by_height&items={items}&offset=0");
        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_array().unwrap();

        assert_eq!(body.len(), items);

        for ((pool_id, pool_data, _, _), json) in pools.iter().zip(body) {
            let pool_id = Address::new(&chain_config, *pool_id).unwrap();
            assert_eq!(json.get("pool_id").unwrap(), pool_id.as_str(),);

            let decommission_key =
                Address::new(&chain_config, pool_data.decommission_key().clone()).unwrap();
            assert_eq!(
                json.get("decommission_destination").unwrap(),
                decommission_key.as_str(),
            );
            assert_eq!(
                json.get("staker_balance").unwrap(),
                &serde_json::json!(amount_to_json(
                    pool_data.pledge(),
                    chain_config.coin_decimals()
                ))
            );

            assert_eq!(
                json.get("margin_ratio_per_thousand").unwrap(),
                &serde_json::json!(pool_data.margin_ratio_per_thousand())
            );

            assert_eq!(
                json.get("cost_per_block").unwrap(),
                &serde_json::json!(amount_to_json(
                    pool_data.cost_per_block(),
                    chain_config.coin_decimals()
                ))
            );

            let vrf_key = Address::new(&chain_config, pool_data.vrf_public_key().clone()).unwrap();
            assert_eq!(
                json.get("vrf_public_key").unwrap(),
                &serde_json::json!(vrf_key.as_str())
            );
        }
    }

    {
        pools.sort_by_key(|x| Reverse(x.1.pledge()));
        let items = pools.len();
        let url = format!("/api/v2/pool?sort=by_pledge&items={items}&offset=0");
        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_array().unwrap();

        assert_eq!(body.len(), items);

        for ((pool_id, pool_data, _, _), json) in pools.iter().zip(body) {
            let pool_id = Address::new(&chain_config, *pool_id).unwrap();
            assert_eq!(json.get("pool_id").unwrap(), pool_id.as_str(),);

            let decommission_key =
                Address::new(&chain_config, pool_data.decommission_key().clone()).unwrap();
            assert_eq!(
                json.get("decommission_destination").unwrap(),
                decommission_key.as_str(),
            );
            assert_eq!(
                json.get("staker_balance").unwrap(),
                &serde_json::json!(amount_to_json(
                    pool_data.pledge(),
                    chain_config.coin_decimals()
                ))
            );

            assert_eq!(
                json.get("margin_ratio_per_thousand").unwrap(),
                &serde_json::json!(pool_data.margin_ratio_per_thousand())
            );

            assert_eq!(
                json.get("cost_per_block").unwrap(),
                &serde_json::json!(amount_to_json(
                    pool_data.cost_per_block(),
                    chain_config.coin_decimals()
                ))
            );

            let vrf_key = Address::new(&chain_config, pool_data.vrf_public_key().clone()).unwrap();
            assert_eq!(
                json.get("vrf_public_key").unwrap(),
                &serde_json::json!(vrf_key.as_str())
            );
        }
    }

    task.abort();
}

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

    shutdown_task(task).await;
}

#[tokio::test]
async fn invalid_num_items() {
    let (task, response) = spawn_webserver("/api/v2/pool?items=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid number of items");

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn invalid_num_items_max(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let more_than_max = rng.random_range(101..1000);
    let (task, response) = spawn_webserver(&format!("/api/v2/pool?items={more_than_max}")).await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid number of items");

    shutdown_task(task).await;
}

#[tokio::test]
async fn invalid_sort_order() {
    let (task, response) = spawn_webserver("/api/v2/pool?sort=asd").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid pools sort order");

    shutdown_task(task).await;
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

                let stake_pool_outpoint = UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );
                let mut available_amount = ((chain_config.min_stake_pool_pledge() * 10).unwrap()
                    + Amount::from_atoms(10000))
                .unwrap();

                let (_, pools) = (0..rng.random_range(1..5)).fold(
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

                        let (transfer_outpoint, delegations) = (0..rng.random_range(0..5)).fold(
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
                    blocks.push(pool.3.clone());
                    for delegation in &pool.2 {
                        for block in &delegation.3 {
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
                stream_events: Default::default(),
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

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn pools_cursor_pagination(#[case] seed: Seed) {
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

                let mut stake_pool_outpoint = UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );
                let mut available_amount = ((chain_config.min_stake_pool_pledge() * 10).unwrap()
                    + Amount::from_atoms(10000))
                .unwrap();

                let mut pool_ids = vec![];
                let mut blocks = vec![];
                for _ in 0..3 {
                    let (transfer_outpoint, _stake_pool_data, pool_id, block) = prepare_stake_pool(
                        stake_pool_outpoint,
                        &mut rng,
                        &mut available_amount,
                        &mut tf,
                    );
                    stake_pool_outpoint = transfer_outpoint;
                    pool_ids.push(pool_id);
                    blocks.push(block);
                }

                let pool_ids = pool_ids
                    .iter()
                    .map(|pool_id| Address::new(&chain_config, *pool_id).unwrap().into_string())
                    .collect::<Vec<_>>();
                _ = tx.send(pool_ids);

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
                stream_events: Default::default(),
            }
        };

        web_server(listener, web_server_state, true).await
    });

    let created_pools = rx.await.unwrap();
    let expected_order = created_pools.iter().rev().collect::<Vec<_>>();

    let get_json = |url: String| async move {
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();
        (response.status(), response.text().await.unwrap())
    };

    // the whole list, unpaged
    {
        let (status, body) = get_json("/api/v2/pool?offset=0&items=100".to_owned()).await;
        assert_eq!(status, 200);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        for (expected_pool_id, json) in expected_order.iter().zip(arr) {
            assert_eq!(
                json.get("pool_id").unwrap().as_str().unwrap(),
                *expected_pool_id
            );
        }
    }

    // the same list, walked with the cursor
    {
        let mut url = "/api/v2/pool?items=1&cursor=".to_owned();
        let mut paged_order = vec![];
        loop {
            // bounded by the known pool count so a self-referencing cursor fails
            // instead of hanging
            assert!(
                paged_order.len() < expected_order.len(),
                "cursor walk exceeded the expected pool count"
            );
            let (status, body) = get_json(url.clone()).await;
            assert_eq!(status, 200);
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();

            let items = body["items"].as_array().unwrap();
            assert_eq!(items.len(), 1);
            paged_order.push(items[0]["pool_id"].as_str().unwrap().to_owned());

            match body["next_cursor"].as_str() {
                Some(cursor) => url = format!("/api/v2/pool?items=1&cursor={cursor}"),
                None => break,
            }
        }
        assert_eq!(paged_order.len(), 3);
        assert_eq!(
            paged_order,
            expected_order.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        );
    }

    // a cursor is only supported by the default sort order
    {
        let (status, body) = get_json("/api/v2/pool?sort=by_pledge&cursor=xyz".to_owned()).await;
        assert_eq!(status, 400);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"].as_str().unwrap(), "Bad request");
    }

    // an invalid cursor is rejected
    {
        let (status, body) = get_json("/api/v2/pool?cursor=garbage".to_owned()).await;
        assert_eq!(status, 400);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"].as_str().unwrap(), "Invalid cursor");
    }

    // a zero page size is rejected
    {
        let (status, body) = get_json("/api/v2/pool?items=0".to_owned()).await;
        assert_eq!(status, 400);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"].as_str().unwrap(), "Invalid number of items");
    }

    shutdown_task(task).await;
}

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

use common::{
    chain::{config::create_regtest, stakelock::StakePoolData, CoinUnit, PoolId},
    primitives::{per_thousand::PerThousand, H256},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};

use super::*;

#[tokio::test]
async fn invalid_pool_id() {
    let (task, response) =
        spawn_webserver("/api/v2/pool/invalid-transaction-id/block-stats?from=0&to=0").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid pool Id");

    task.abort();
}

#[tokio::test]
async fn from_to_not_specified() {
    let pool_id = PoolId::new(H256::zero());
    let chain_config = create_unit_test_config();
    let pool_id = Address::new(&chain_config, pool_id).unwrap();
    let (task, response) = spawn_webserver(&format! {"/api/v2/pool/{pool_id}/block-stats"}).await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    assert_eq!(
        body,
        "Failed to deserialize query string: missing field `from`"
    );

    task.abort();
}

#[tokio::test]
async fn pool_id_not_fund() {
    let pool_id = PoolId::new(H256::zero());
    let chain_config = create_unit_test_config();
    let pool_id = Address::new(&chain_config, pool_id).unwrap();
    let (task, response) =
        spawn_webserver(&format! {"/api/v2/pool/{pool_id}/block-stats?from=0&to=0"}).await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Stake pool not found");

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

            let initial_pledge = 40_000 * CoinUnit::ATOMS_PER_COIN + rng.gen_range(10000..100000);
            let (staking_sk, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
            let staking_key = Destination::PublicKey(pk.clone());
            let pool_data = StakePoolData::new(
                Amount::from_atoms(initial_pledge),
                staking_key.clone(),
                vrf_pk,
                staking_key.clone(),
                PerThousand::new_from_rng(&mut rng),
                Amount::from_atoms(rng.gen_range(0..100)),
            );
            let pool_id = PoolId::new(H256::random_using(&mut rng));

            let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
                Amount::from_atoms(initial_pledge * 2),
                pool_id,
                pool_data,
            )
            .build();
            let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
            let chain_config = Arc::clone(tf.chainstate.get_chain_config());
            let target_block_time = chain_config.target_block_spacing();
            let prev_block_hash = chain_config.genesis_block_id();

            let chainstate_blocks = {
                let (_, blocks) = (0..rng.gen_range(1..100)).fold(
                    (prev_block_hash, vec![]),
                    |(prev_block_hash, mut blocks), _| {
                        tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

                        let block = tf
                            .make_pos_block_builder()
                            .with_parent(prev_block_hash)
                            .with_stake_spending_key(staking_sk.clone())
                            .with_vrf_key(vrf_sk.clone())
                            .with_stake_pool(pool_id)
                            .build();
                        tf.process_block(block.clone(), BlockSource::Local).unwrap();

                        let prev_block_hash = block.get_id().into();
                        blocks.push(block);

                        (prev_block_hash, blocks)
                    },
                );

                let num_blocks = rng.gen_range(0..blocks.len());
                let time_range = (
                    blocks.first().unwrap().timestamp(),
                    blocks[num_blocks].timestamp(),
                );

                _ = tx.send((pool_id, num_blocks, time_range));

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

    let chain_config = create_regtest();
    let (pool_id, num_blocks, (from, to)) = rx.await.unwrap();
    let pool_id = Address::new(&chain_config, pool_id).unwrap();
    let url = format!("/api/v2/pool/{pool_id}/block-stats?from={from}&to={to}");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    // assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprint!("body {body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(body.get("block_count").unwrap(), num_blocks);

    task.abort();
}

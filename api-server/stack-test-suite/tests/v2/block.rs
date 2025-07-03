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

use api_server_common::storage::storage_api::{ApiServerStorageRead, TxAdditionalInfo};
use common::{
    chain::{stakelock::StakePoolData, CoinUnit, GenBlock, PoolId},
    primitives::{per_thousand::PerThousand, time::get_time, H256},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use std::{collections::BTreeMap, sync::RwLock};

use api_web_server::{
    api::json_helpers::{block_header_to_json, tx_to_json, txoutput_to_json},
    CachedValues,
};

use crate::DummyRPC;

use super::*;

#[tokio::test]
async fn invalid_block_id() {
    let (task, response) = spawn_webserver("/api/v2/block/invalid-block-id").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");

    task.abort();
}

#[tokio::test]
async fn block_not_found() {
    let (task, response) = spawn_webserver(
        "/api/v2/block/0000000000000000000000000000000000000000000000000000000000000001",
    )
    .await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Block not found");

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

    let mut rng = make_seedable_rng(seed);
    let block_height = rng.gen_range(2..50);
    let task = tokio::spawn(async move {
        let web_server_state = {
            let n_blocks = rng.gen_range(block_height..100);

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
                &mut rng,
                Amount::from_atoms(initial_pledge * 2),
                pool_id,
                pool_data,
            )
            .build();
            let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

            let target_block_time = tf.chain_config().target_block_spacing();
            let mut prev_block_hash: Id<GenBlock> = tf.chain_config().genesis_block_id();

            let chainstate_blocks: Vec<_> = (0..n_blocks)
                .map(|_| {
                    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
                    let block = tf
                        .make_pos_block_builder()
                        .with_parent(prev_block_hash)
                        .with_stake_spending_key(staking_sk.clone())
                        .with_vrf_key(vrf_sk.clone())
                        .with_stake_pool_id(pool_id)
                        .build(&mut rng);
                    prev_block_hash = block.get_id().into();
                    tf.process_block(block.clone(), BlockSource::Local).unwrap();
                    block
                })
                .collect();

            let storage = {
                let chain_config = tf.chain_config();
                let mut storage = TransactionalApiServerInMemoryStorage::new(chain_config);

                let mut db_tx = storage.transaction_rw().await.unwrap();
                db_tx.reinitialize_storage(chain_config).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            // Get the current block at block_height
            // Need the "- 1" to account for the genesis block not in the vec
            let old_block_id = chainstate_blocks.get(block_height - 1).unwrap().get_id().into();
            let block = tf.block(tf.to_chain_block_id(&old_block_id));

            // Scan those blocks
            let mut local_node = BlockchainState::new(tf.chain_config().clone(), storage);
            local_node.scan_genesis(tf.chain_config().genesis_block()).await.unwrap();
            local_node
                .scan_blocks(BlockHeight::new(0), chainstate_blocks.clone())
                .await
                .unwrap();

            let tx_additional_data = get_tx_additional_data(&local_node, &block).await;

            let old_expected_block = json!({
                "height": None::<BlockHeight>,
                "header": block_header_to_json(&block),
                "body": {
                    "reward": block.block_reward()
                        .outputs()
                        .iter()
                        .map(|out| txoutput_to_json(out, tf.chain_config(), &TokenDecimals::Single(None)))
                        .collect::<Vec<_>>(),
                    "transactions": block.transactions()
                                        .iter()
                                        .zip(tx_additional_data.iter())
                                        .map(|(tx, additional_data)| tx_to_json(tx, additional_data, tf.chain_config()))
                                        .collect::<Vec<_>>(),
                },
            });

            // create a reorg
            let parent_block = chainstate_blocks.get(block_height - 2).unwrap();
            let mut prev_block_hash = parent_block.get_id().into();
            let count = rng.gen_range(block_height..=100);
            tf.set_time_seconds_since_epoch(parent_block.timestamp().as_int_seconds());

            let new_chainstate_blocks: Vec<_> = (block_height - 1..count)
                .map(|_| {
                    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
                    let block = tf
                        .make_pos_block_builder()
                        .with_parent(prev_block_hash)
                        .with_stake_spending_key(staking_sk.clone())
                        .with_vrf_key(vrf_sk.clone())
                        .with_stake_pool_id(pool_id)
                        .build(&mut rng);
                    prev_block_hash = block.get_id().into();
                    tf.process_block(block.clone(), BlockSource::Local).unwrap();
                    block
                })
                .collect();

            let block = new_chainstate_blocks[0].clone();
            let block_id = block.get_id();

            local_node
                .scan_blocks(
                    BlockHeight::new((block_height - 1) as u64),
                    new_chainstate_blocks,
                )
                .await
                .unwrap();

            let tx_additional_data = get_tx_additional_data(&local_node, &block).await;

            let new_expected_block = json!({
                "height": block_height,
                "header": block_header_to_json(&block),
                "body": {
                    "reward": block.block_reward()
                        .outputs()
                        .iter()
                        .map(|out| txoutput_to_json(out, tf.chain_config(), &TokenDecimals::Single(None)))
                        .collect::<Vec<_>>(),
                    "transactions": block.transactions()
                                        .iter()
                                        .zip(tx_additional_data.iter())
                                        .map(|(tx, additinal_data)| tx_to_json(tx, additinal_data, tf.chain_config()))
                                        .collect::<Vec<_>>(),
                },
            });

            _ = tx.send((
                block_id.to_hash().encode_hex::<String>(),
                new_expected_block,
                old_block_id.to_hash().encode_hex::<String>(),
                old_expected_block,
            ));

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config: tf.chain_config().clone(),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((get_time(), vec![])),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, true).await
    });

    let (block_id, new_expected_block, old_block_id, old_expected_block) = rx.await.unwrap();
    let url = format!("/api/v2/block/{block_id}");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body, new_expected_block);

    let url = format!("/api/v2/block/{old_block_id}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body, old_expected_block);
    task.abort();
}

async fn get_tx_additional_data(
    local_node: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    block: &common::chain::Block,
) -> Vec<TxAdditionalInfo> {
    let db_tx = local_node.storage().transaction_ro().await.unwrap();
    let mut tx_additional_data = vec![];
    for tx in block.transactions() {
        let mut input_utxos = vec![];
        for input in tx.inputs() {
            let utxo = match input {
                TxInput::Utxo(outpoint) => {
                    db_tx.get_utxo(outpoint.clone()).await.unwrap().map(|utxo| utxo.into_output())
                }
                TxInput::Account(_)
                | TxInput::AccountCommand(_, _)
                | TxInput::OrderAccountCommand(_) => None,
            };
            input_utxos.push(utxo);
        }

        tx_additional_data.push(TxAdditionalInfo {
            input_utxos,
            fee: Amount::ZERO,
            token_decimals: BTreeMap::new(),
        });
    }
    tx_additional_data
}

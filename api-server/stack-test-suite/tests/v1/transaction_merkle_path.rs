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

use super::*;

use api_server_common::storage::storage_api::{
    block_aux_data::{BlockAuxData, BlockWithExtraData},
    TransactionInfo, TxAdditionalInfo,
};
use common::{
    chain::{block::timestamp::BlockTimestamp, Block},
    primitives::{Id, H256},
};
use std::str::FromStr;

#[tokio::test]
async fn get_transaction_failed() {
    let (task, response) = spawn_webserver("/api/v1/transaction/invalid-txid/merkle-path").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid transaction Id");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn get_block_failed(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let block_height = rng.gen_range(1..50);
            let n_blocks = rng.gen_range(block_height..100);

            let chain_config = create_unit_test_config();

            let (chainstate_blocks, signed_transaction, transaction_id) = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let chainstate_block_ids = tf
                    .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                    .unwrap();

                // Need the "- 1" to account for the genesis block not in the vec
                let block_id = chainstate_block_ids[block_height - 1];
                let block = tf.block(tf.to_chain_block_id(&block_id));

                let transaction_index = rng.gen_range(0..block.transactions().len());
                let signed_transaction = block.transactions()[transaction_index].clone();
                let transaction = signed_transaction.transaction();
                let transaction_id = transaction.get_id();

                _ = tx.send(transaction_id.to_hash().encode_hex::<String>());

                (
                    chainstate_block_ids
                        .iter()
                        .map(|id| tf.block(tf.to_chain_block_id(id)))
                        .collect::<Vec<_>>(),
                    signed_transaction,
                    transaction_id,
                )
            };

            let mut storage = {
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

            storage = {
                let mut storage = local_node.storage().clone_storage().await;
                let mut db_tx = storage.transaction_rw().await.unwrap();

                let block_id: Id<Block> = H256::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap()
                .into();

                let tx_info = TransactionInfo {
                    tx: signed_transaction,
                    additinal_info: TxAdditionalInfo {
                        fee: Amount::from_atoms(rng.gen_range(0..100)),
                        input_utxos: vec![],
                        token_decimals: BTreeMap::new(),
                    },
                };

                db_tx.set_transaction(transaction_id, Some(block_id), &tx_info).await.unwrap();

                db_tx
                    .set_block_aux_data(
                        block_id,
                        &BlockAuxData::new(
                            block_id.into(),
                            BlockHeight::new(rng.gen::<u32>() as u64),
                            BlockTimestamp::from_int_seconds(rng.gen::<u64>()),
                        ),
                    )
                    .await
                    .unwrap();

                db_tx.commit().await.unwrap();

                storage
            };

            ApiServerWebServerState {
                db: Arc::new(storage),
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

    let transaction_id = rx.await.unwrap();
    let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Block not found");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn transaction_not_part_of_block(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let block_height = rng.gen_range(1..50);
            let n_blocks = rng.gen_range(block_height..100);

            let chain_config = create_unit_test_config();

            let (chainstate_blocks, signed_transaction, transaction_id) = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let chainstate_block_ids = tf
                    .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                    .unwrap();

                // Need the "- 1" to account for the genesis block not in the vec
                let block_id = chainstate_block_ids[block_height - 1];
                let block = tf.block(tf.to_chain_block_id(&block_id));

                let transaction_index = rng.gen_range(0..block.transactions().len());
                let transaction = block.transactions()[transaction_index].transaction();
                let transaction_id = transaction.get_id();

                _ = tx.send(transaction_id.to_hash().encode_hex::<String>());

                (
                    chainstate_block_ids
                        .iter()
                        .map(|id| tf.block(tf.to_chain_block_id(id)))
                        .collect::<Vec<_>>(),
                    block.transactions()[transaction_index].clone(),
                    transaction_id,
                )
            };

            let mut storage = {
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

            storage = {
                let mut storage = local_node.storage().clone_storage().await;
                let mut db_tx = storage.transaction_rw().await.unwrap();

                let tx_info = TransactionInfo {
                    tx: signed_transaction,
                    additinal_info: TxAdditionalInfo {
                        fee: Amount::from_atoms(rng.gen_range(0..100)),
                        input_utxos: vec![],
                        token_decimals: BTreeMap::new(),
                    },
                };
                db_tx.set_transaction(transaction_id, None, &tx_info).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            ApiServerWebServerState {
                db: Arc::new(storage),
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

    let transaction_id = rx.await.unwrap();
    let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Transaction not part of any block"
    );

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn cannot_find_transaction_in_block(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let mut rng = make_seedable_rng(seed);
    let block_height = rng.gen_range(1..50);
    let task = tokio::spawn(async move {
        let web_server_state = {
            let n_blocks = rng.gen_range(block_height..100);

            let chain_config = create_unit_test_config();

            let (chainstate_blocks, block, block_id) = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let chainstate_block_ids = tf
                    .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                    .unwrap();

                // Need the "- 1" to account for the genesis block not in the vec
                let block_id = chainstate_block_ids[block_height - 1];
                let block = tf.block(tf.to_chain_block_id(&block_id));

                let transaction_index = rng.gen_range(0..block.transactions().len());
                let transaction = block.transactions()[transaction_index].transaction();
                let transaction_id = transaction.get_id();

                _ = tx.send(transaction_id.to_hash().encode_hex::<String>());

                (
                    chainstate_block_ids
                        .iter()
                        .map(|id| tf.block(tf.to_chain_block_id(id)))
                        .collect::<Vec<_>>(),
                    block,
                    block_id,
                )
            };

            let mut storage = {
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

            storage = {
                let mut storage = local_node.storage().clone_storage().await;
                let mut db_tx = storage.transaction_rw().await.unwrap();

                let empty_block = Block::new(
                    vec![],
                    block.prev_block_id(),
                    block.timestamp(),
                    block.consensus_data().clone(),
                    block.block_reward().clone(),
                )
                .unwrap();
                let empty_block = BlockWithExtraData {
                    block: empty_block,
                    tx_additional_infos: vec![],
                };

                db_tx
                    .set_mainchain_block(
                        block_id.classify(&chain_config).chain_block_id().unwrap(),
                        BlockHeight::new(block_height as u64),
                        &empty_block,
                    )
                    .await
                    .unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            ApiServerWebServerState {
                db: Arc::new(storage),
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

    let transaction_id = rx.await.unwrap();
    let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 500);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Cannot find transaction in block"
    );

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
            let block_height = rng.gen_range(1..50);
            let n_blocks = rng.gen_range(block_height..100);

            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                let chainstate_block_ids = tf
                    .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                    .unwrap();

                // Need the "- 1" to account for the genesis block not in the vec
                let block_id = chainstate_block_ids[block_height - 1];
                let block = tf.block(tf.to_chain_block_id(&block_id));

                let transaction_index = rng.gen_range(0..block.transactions().len());
                let transaction = block.transactions()[transaction_index].transaction();
                let transaction_id = transaction.get_id();

                let merkle_proxy = block.body().merkle_tree_proxy().unwrap();
                let merkle_tree = merkle_proxy
                    .merkle_tree()
                    .transaction_inclusion_proof(transaction_index.try_into().unwrap())
                    .unwrap()
                    .into_hashes();

                let expected_path = json!({
                "block_id": block_id.to_hash().encode_hex::<String>(),
                "transaction_index": transaction_index,
                "merkle_root": block.merkle_root().encode_hex::<String>(),
                "merkle_path": merkle_tree.into_iter().map(
                    |hash| hash.encode_hex::<String>()).collect::<Vec<_>>(),
                });

                _ = tx.send((
                    transaction_id.to_hash().encode_hex::<String>(),
                    expected_path,
                ));

                chainstate_block_ids
                    .iter()
                    .map(|id| tf.block(tf.to_chain_block_id(id)))
                    .collect::<Vec<_>>()
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

    let (transaction_id, expected_path) = rx.await.unwrap();
    let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body, expected_path);

    task.abort();
}

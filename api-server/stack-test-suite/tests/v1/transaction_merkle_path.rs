use super::*;

#[tokio::test]
async fn get_transaction_failed() {
    let (task, response) =
        spawn_webserver("/api/v1/transaction/invalid-txid/merkle-path").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid transaction Id");

    task.abort();
}

// TODO I wanted to delete the block from the database so that
// get_block() fails within transaction_merkle_path(). However it
// looks like the block is not being deleted
//
// #[rstest]
// #[trace]
// #[case(Seed::from_entropy())]
// #[tokio::test]
// async fn get_block_failed(#[case] seed: Seed) {
//     let listener = TcpListener::bind("127.0.0.1:0").unwrap();
//     let addr = listener.local_addr().unwrap();

//     let (tx, rx) = tokio::sync::oneshot::channel();

//     let task = tokio::spawn(async move {
//         let web_server_state = {
//             let mut rng = make_seedable_rng(seed);
//             let block_height = rng.gen_range(1..50);
//             let n_blocks = rng.gen_range(block_height..100);

//             let chain_config = create_unit_test_config();

//             let chainstate_blocks = {
//                 let mut tf = TestFramework::builder(&mut rng)
//                     .with_chain_config(chain_config.clone())
//                     .build();

//                 let chainstate_block_ids = tf
//                     .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
//                     .unwrap();

//                 // Need the "- 1" to account for the genesis block not in the vec
//                 let block_id = chainstate_block_ids[block_height - 1];

//                 let block = tf.block(tf.to_chain_block_id(&block_id));

//                 let transaction_index = rng.gen_range(0..block.transactions().len());
//                 let transaction = block.transactions()[transaction_index].transaction();
//                 let transaction_id = transaction.get_id();

//                 _ = tx.send(transaction_id.to_hash().encode_hex::<String>());

//                 chainstate_block_ids
//                     .iter()
//                     .map(|id| tf.block(tf.to_chain_block_id(id)))
//                     .collect::<Vec<_>>()
//             };

//             let mut storage = {
//                 let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

//                 let mut db_tx = storage.transaction_rw().await.unwrap();
//                 db_tx.initialize_storage(&chain_config).await.unwrap();
//                 db_tx.commit().await.unwrap();

//                 storage
//             };

//             let mut local_node = BlockchainState::new(storage);
//             local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

//             storage = local_node.storage().clone_storage().await;

//             {
//                 let mut db_tx = storage.transaction_rw().await.unwrap();

//                 db_tx
//                     .del_main_chain_block_id(BlockHeight::new(
//                         (block_height - 1).try_into().unwrap(),
//                     ))
//                     .await
//                     .unwrap();

//                 db_tx.commit().await.unwrap();
//             }

//             ApiServerWebServerState {
//                 db: Arc::new(storage),
//                 chain_config: Arc::new(chain_config),
//             }
//         };

//         web_server(listener, web_server_state).await
//     });

//     let transaction_id = rx.await.unwrap();
//     let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

//     let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
//         .await
//         .unwrap();

//     assert_eq!(response.status(), 400);

//     let body = response.text().await.unwrap();
//     let body: serde_json::Value = serde_json::from_str(&body).unwrap();
//     let body = body.as_object().unwrap();

//     assert_eq!(body["error"].as_str().unwrap(), "Block not found");

// 	task.abort();
// }

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

            let mut local_node = BlockchainState::new(storage);
            local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

            storage = local_node.storage().clone_storage().await;

            {
                // TODO to test this I wanted to delete the block
                // from the database so that get_block() fails
                // within transaction_merkle_path(). However it
                // looks like this isn't deleting the block

                let mut db_tx = storage.transaction_rw().await.unwrap();

                db_tx.set_transaction(transaction_id, None, &signed_transaction).await.unwrap();

                db_tx.commit().await.unwrap();
            }

            ApiServerWebServerState {
                db: Arc::new(storage),
                chain_config: Arc::new(chain_config),
            }
        };

        web_server(listener, web_server_state).await
    });

    let transaction_id = rx.await.unwrap();
    let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Transaction not part of any block"
    );

    task.abort();
}

// TODO tests for:
//
// - CannotFindTransactionInBlock
// - TransactionIndexOverflow
// - ErrorCalculatingMerkleTree
// - ErrorCalculatingMerklePath

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

                let expected_transaction = json!({
                "block_id": block_id.to_hash().encode_hex::<String>(),
                "transaction_index": transaction_index,
                "merkle_root": block.merkle_root().encode_hex::<String>(),
                "merkle_path": merkle_tree.into_iter().map(
                    |hash| hash.encode_hex::<String>()).collect::<Vec<_>>(),
                });

                _ = tx.send((
                    block_id.to_hash().encode_hex::<String>(),
                    transaction_id.to_hash().encode_hex::<String>(),
                    expected_transaction,
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

            let mut local_node = BlockchainState::new(storage);
            local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config: Arc::new(chain_config),
            }
        };

        web_server(listener, web_server_state).await
    });

    let (block_id, transaction_id, expected_transaction) = rx.await.unwrap();
    let url = format!("/api/v1/transaction/{transaction_id}/merkle-path");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(body.get("block_id").unwrap(), &block_id);
    assert_eq!(
        body.get("transaction_index").unwrap(),
        expected_transaction.get("transaction_index").unwrap()
    );
    assert_eq!(
        body.get("merkle_root").unwrap(),
        expected_transaction.get("merkle_root").unwrap()
    );

    for (index, hash) in body.get("merkle_path").unwrap().as_array().unwrap().iter().enumerate()
    {
        assert_eq!(
            hash,
            expected_transaction.get("merkle_path").unwrap().get(index).unwrap()
        );
    }

    task.abort();
}

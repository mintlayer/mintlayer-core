use super::*;

#[tokio::test]
async fn invalid_block_id() {
    let (task, response) = spawn_webserver("/api/v1/block/invalid-block-id").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid block Id");

    task.abort();
}

#[tokio::test]
async fn block_not_found() {
    let (task, response) = spawn_webserver(
        "/api/v1/block/0000000000000000000000000000000000000000000000000000000000000001",
    )
    .await;

    assert_eq!(response.status(), 400);

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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let block_height = rng.gen_range(1..50);
            let n_blocks = rng.gen_range(block_height..100);

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

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

                let expected_block = json!({
                    "previous_block_id": block.prev_block_id().to_hash().encode_hex::<String>(),
                    "timestamp": block.timestamp(),
                    "merkle_root": block.merkle_root().encode_hex::<String>(),
                });

                _ = tx.send((block_id.to_hash().encode_hex::<String>(), expected_block));

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

    let (block_id, expected_block) = rx.await.unwrap();
    let url = format!("/api/v1/block/{block_id}");

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let body = body.as_object().unwrap();

    assert_eq!(
        body.get("previous_block_id").unwrap(),
        &expected_block["previous_block_id"]
    );
    assert_eq!(body.get("timestamp").unwrap(), &expected_block["timestamp"]);
    assert_eq!(
        body.get("merkle_root").unwrap(),
        &expected_block["merkle_root"]
    );

    assert!(body.contains_key("transactions"));

    // TODO check transactions fields
    // assert...

    task.abort();
}

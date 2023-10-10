use super::*;

#[tokio::test]
async fn invalid_height() {
    let (task, response) = spawn_webserver("/api/v1/chain/invalid-height").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid block height");

    task.abort();
}

#[tokio::test]
async fn height_zero() {
    let (task, response) = spawn_webserver("/api/v1/chain/0").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "No block found at supplied height"
    );

    task.abort();
}

#[tokio::test]
async fn height_past_tip() {
    let (task, response) = spawn_webserver("/api/v1/chain/1337").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "No block found at supplied height"
    );

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn height_n(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let block_height = rng.gen_range(1..50);
    let n_blocks = rng.gen_range(block_height..100);
    let url = format!("/api/v1/chain/{block_height}");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn({
        async move {
            let web_server_state = {
                let chain_config = create_unit_test_config();

                let chainstate_blocks = {
                    let mut tf = TestFramework::builder(&mut rng)
                        .with_chain_config(chain_config.clone())
                        .build();

                    let chainstate_block_ids = tf
                        .create_chain_return_ids(&tf.genesis().get_id().into(), n_blocks, &mut rng)
                        .unwrap();

                    // Need the "- 1" to account for the genesis block not in the vec
                    let expected_block_id = chainstate_block_ids[block_height - 1];

                    _ = tx.send(expected_block_id);

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
        }
    });

    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let expected_block_id = rx.await.unwrap();

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body.as_str().unwrap(),
        expected_block_id.to_hash().encode_hex::<String>()
    );

    task.abort();
}

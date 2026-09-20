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

//! End-to-end test of the real-time event streaming over Postgres:
//! scanner -> emitted_events -> event pump -> SSE endpoint, including a reorg.
//!
//! Note: the scanner side is driven through the public `BlockchainState` API, which is the exact
//! code path `sync_once` delegates to for applying blocks (including the stream event appends and
//! the pg_notify wakeup inside the same transaction).

// Note: the module must not be called `common`, which would be ambiguous with the `common`
// workspace crate; the path attribute decouples the module name from the file name.
#[path = "common/mod.rs"]
mod test_common;

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use api_blockchain_scanner_lib::{
    blockchain_state::BlockchainState, sync::local_state::LocalBlockchainState,
};
use api_server_backend_test_suite::podman::{Container, Podman};
use api_server_common::storage::{
    impls::postgres::{PostgresStreamEventSource, TransactionalApiServerPostgresStorage},
    storage_api::{ApiServerStorageWrite, ApiServerTransactionRw, Transactional},
};
use api_server_common::streaming::{StreamEvent, StreamEventsChannel};
use api_web_server::{
    ApiServerWebServerState, CachedValues, StreamEventsHandle, StreamingConfig, api::web_server,
    streaming::run_database_event_pump,
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::Block,
    primitives::{BlockHeight, Id, Idable, time::get_time},
};
use hex::ToHex as _;
use test_common::{DummyRPC, frame_data, frame_event_name, shutdown_webserver};
use test_utils::random::{Seed, make_seedable_rng};

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

/// The time to wait for a single expected stream event.
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Receive the next stream event from the collector, failing if it doesn't arrive in time.
async fn recv_event(
    event_rx: &mut tokio::sync::mpsc::UnboundedReceiver<(String, StreamEvent)>,
) -> (String, StreamEvent) {
    tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .expect("timed out waiting for a stream event")
        .expect("the stream event collector has been closed")
}

#[tokio::test]
async fn stream_events_postgres_end_to_end() {
    // Only run the test if the env var is defined
    if std::env::var("ML_CONTAINERIZED_TESTS").is_err() {
        eprintln!("Warning: Skipping Postgres containerized tests");
        return;
    }

    let mut rng = make_seedable_rng(Seed::from_entropy());
    let mut tf = TestFramework::builder(&mut rng).build();
    let chain_config = tf.chain_config().clone();

    // -----------------------------------------------------------------------------------------
    // The Postgres container and two storage instances (two pools), mirroring the scanner and
    // the web server processes.
    // -----------------------------------------------------------------------------------------
    // Note: starting the container involves blocking process invocations (podman/docker CLI),
    // which must not run on the runtime thread, where they would starve the async tasks spawned
    // below and potentially distort the timing-sensitive assertions. The `Podman` handle is
    // returned (rather than dropped inside the blocking task) so that the container is still
    // cleaned up by its destructor when the test ends.
    let (_podman, host_port) = {
        let chain_config = Arc::clone(&chain_config);
        tokio::task::spawn_blocking(move || {
            let mut podman = Podman::new(
                "MintlayerPostgresStreamTest",
                Container::PostgresFromDockerHub,
            )
            .with_env("POSTGRES_HOST_AUTH_METHOD", "trust")
            .with_env(
                "POSTGRES_DB",
                format!("mintlayer-{}", chain_config.chain_type().name()).as_str(),
            )
            .with_port_mapping(None, 5432);
            podman.run();

            let host_port = podman.get_port_mapping(5432).unwrap();
            (podman, host_port)
        })
        .await
        .unwrap()
    };
    let new_storage = || {
        TransactionalApiServerPostgresStorage::new(
            "127.0.0.1",
            host_port,
            "postgres",
            None,
            None,
            5,
            chain_config.clone(),
        )
    };

    let mut scanner_storage = new_storage().await.unwrap();
    let web_storage = Arc::new(new_storage().await.unwrap());

    // Initialize the schema.
    {
        let mut db_tx = scanner_storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();
    }

    // -----------------------------------------------------------------------------------------
    // Start the event pump first, then the web server.
    // -----------------------------------------------------------------------------------------
    let handle = StreamEventsHandle::new(
        StreamEventsChannel::new(64),
        StreamingConfig {
            keepalive_interval: Duration::from_millis(200),
            max_subscribers: 8,
        },
    );
    let event_listener = web_storage.new_event_listener().await.unwrap();
    let source = PostgresStreamEventSource::new(
        Arc::clone(&web_storage),
        event_listener,
        Duration::from_millis(200),
    );
    tokio::spawn(run_database_event_pump(source, handle.clone()));

    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = http_listener.local_addr().unwrap();

    let web_storage_for_task = Arc::clone(&web_storage);
    let chain_config_for_task = Arc::clone(&chain_config);
    let web_task = tokio::spawn(async move {
        let web_server_state = ApiServerWebServerState {
            db: web_storage_for_task,
            chain_config: chain_config_for_task,
            rpc: Arc::new(DummyRPC {}),
            cached_values: Arc::new(CachedValues {
                feerate_points: RwLock::new((get_time(), vec![])),
            }),
            time_getter: Default::default(),
            stream_events: handle,
        };

        web_server(http_listener, web_server_state, true).await.unwrap();
    });

    // -----------------------------------------------------------------------------------------
    // The SSE connection and the event collector. The collector is fed by a task reading the
    // event stream; the test waits for the connection to be established before any event is
    // produced, since a stream subscriber must exist for the pump's sends to reach it.
    // -----------------------------------------------------------------------------------------
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<(String, StreamEvent)>();
    let (connected_tx, connected_rx) = tokio::sync::oneshot::channel::<()>();

    let sse_url = format!("http://{}:{}/api/v2/stream", addr.ip(), addr.port());
    // Note: the handle is kept so that the task can be joined at the end of the test; otherwise
    // a panic inside the collector (an assertion, a serde unwrap, a UTF-8 unwrap) would only
    // surface as a misleading timeout or a closed-channel error elsewhere.
    let collector_task = tokio::spawn(async move {
        let mut connect_attempts = 0u32;
        let client = reqwest::Client::new();
        // Note: the listener is already bound, so this connect resolves as soon as the web
        // server has taken the listener over; retry in case it hasn't yet.
        let mut response = loop {
            match client.get(&sse_url).send().await {
                Ok(response) if response.status() == 200 => break response,
                _ => {
                    connect_attempts += 1;
                    assert!(
                        connect_attempts < 100,
                        "failed to connect to the stream endpoint"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };

        assert_eq!(
            response
                .headers()
                .get("x-accel-buffering")
                .expect("x-accel-buffering header must be present"),
            "no"
        );

        // Note: fails the test (via the oneshot) if the endpoint cannot be connected to.
        _ = connected_tx.send(());

        let mut buffer = String::new();
        loop {
            let chunk = match tokio::time::timeout(Duration::from_secs(60), response.chunk()).await
            {
                Ok(Ok(Some(chunk))) => chunk,
                // Timed out or the stream ended; either way the collector stops here.
                _ => break,
            };
            buffer.push_str(std::str::from_utf8(&chunk).unwrap());

            while let Some(frame_end) = buffer.find("\n\n") {
                let frame: String = buffer.drain(..frame_end + 2).collect();
                if let (Some(name), Some(data)) = (frame_event_name(&frame), frame_data(&frame)) {
                    let event: StreamEvent =
                        serde_json::from_str(data).expect("the event payload must be valid JSON");
                    if event_tx.send((name.to_owned(), event)).is_err() {
                        // The test has finished; stop collecting.
                        return;
                    }
                }
            }
        }
    });
    connected_rx.await.unwrap();

    let rest_client = reqwest::Client::new();
    let block_url = |block_id: Id<Block>| {
        format!(
            "http://{}:{}/api/v2/block/{}",
            addr.ip(),
            addr.port(),
            block_id.to_hash().encode_hex::<String>()
        )
    };

    // -----------------------------------------------------------------------------------------
    // First sync: three blocks connected on top of genesis must produce exactly three block
    // events, in height order.
    // -----------------------------------------------------------------------------------------
    let mainchain_block_ids = tf
        .create_chain_return_ids(&chain_config.genesis_block_id(), 3, &mut rng)
        .unwrap();
    let mainchain_blocks: Vec<Block> = mainchain_block_ids
        .iter()
        .map(|id| tf.block(tf.to_chain_block_id(id)))
        .collect();

    let mut scanner = BlockchainState::new(chain_config.clone(), scanner_storage);
    scanner.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();
    scanner
        .scan_blocks(BlockHeight::new(0), mainchain_blocks.clone())
        .await
        .unwrap();

    for (idx, block) in mainchain_blocks.iter().enumerate() {
        let expected_event = StreamEvent::Block {
            block_id: block.get_id(),
            height: BlockHeight::new(idx as u64 + 1),
            timestamp: block.timestamp(),
            tx_ids: block.transactions().iter().map(|tx| tx.transaction().get_id()).collect(),
        };

        let (name, event) = recv_event(&mut event_rx).await;
        assert_eq!(name, "block");
        assert_eq!(event, expected_event, "unexpected event for block #{idx}");

        if idx == 0 {
            // Transactional consistency: the block carried by the first event must be
            // immediately queryable through the regular REST endpoint.
            let response = rest_client.get(block_url(block.get_id())).send().await.unwrap();
            assert_eq!(response.status(), 200);

            let body: serde_json::Value =
                serde_json::from_str(&response.text().await.unwrap()).unwrap();
            let served_tx_ids: Vec<String> = body["body"]["transactions"]
                .as_array()
                .expect("transactions must be an array")
                .iter()
                .map(|tx| tx["id"].as_str().expect("tx id must be a string").to_owned())
                .collect();
            let expected_tx_ids: Vec<String> = block
                .transactions()
                .iter()
                .map(|tx| tx.transaction().get_id().to_hash().encode_hex::<String>())
                .collect();
            assert_eq!(served_tx_ids, expected_tx_ids);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Reorg: create a heavier fork from the block at height 1. The previously mainchain blocks
    // at heights 2..3 are removed, the fork blocks at heights 2..4 are connected.
    // -----------------------------------------------------------------------------------------
    let removed_block_ids: Vec<Id<Block>> = [2u64, 3]
        .iter()
        .map(|height| {
            let id = tf
                .chainstate
                .get_block_id_from_height(BlockHeight::new(*height))
                .unwrap()
                .unwrap();
            tf.to_chain_block_id(&id)
        })
        .collect();

    let fork_parent_id =
        tf.chainstate.get_block_id_from_height(BlockHeight::new(1)).unwrap().unwrap();
    let fork_block_ids = tf.create_chain_return_ids(&fork_parent_id, 3, &mut rng).unwrap();
    let fork_blocks: Vec<Block> =
        fork_block_ids.iter().map(|id| tf.block(tf.to_chain_block_id(id))).collect();

    scanner.scan_blocks(BlockHeight::new(1), fork_blocks.clone()).await.unwrap();

    // Exactly one reorg event must arrive, before the events of the new fork blocks.
    let (name, event) = recv_event(&mut event_rx).await;
    assert_eq!(name, "reorg");
    assert_eq!(
        event,
        StreamEvent::Reorg {
            common_ancestor_height: BlockHeight::new(1),
            removed_block_ids: removed_block_ids.clone(),
            new_tip_height: BlockHeight::new(4),
        }
    );

    // Then the block events of the new fork blocks, in height order 2..4.
    for (idx, block) in fork_blocks.iter().enumerate() {
        let expected_event = StreamEvent::Block {
            block_id: block.get_id(),
            height: BlockHeight::new(idx as u64 + 2),
            timestamp: block.timestamp(),
            tx_ids: block.transactions().iter().map(|tx| tx.transaction().get_id()).collect(),
        };

        let (name, event) = recv_event(&mut event_rx).await;
        assert_eq!(name, "block");
        assert_eq!(event, expected_event, "unexpected fork event #{idx}");
    }

    // The removed blocks must still be fetchable: the explorer database keeps disconnected
    // blocks with a null height.
    for removed_block_id in &removed_block_ids {
        let response = rest_client.get(block_url(*removed_block_id)).send().await.unwrap();
        assert_eq!(
            response.status(),
            200,
            "disconnected block must remain fetchable"
        );
    }

    // -----------------------------------------------------------------------------------------
    // No duplicates: connect one sentinel block, await exactly its event, and only then assert
    // that no further events arrive (the expected total is exactly one reorg + 3 + 3 + 1 block
    // events, all of which have been consumed above). Once the sentinel event has arrived,
    // every event committed before it must have been delivered (the pump forwards in commit
    // order), so the settle and observe windows only guard against scheduling latency; they are
    // deliberately generous, so that this assertion does not flake on slow CI machines.
    // -----------------------------------------------------------------------------------------
    let fork_tip_id = tf.chainstate.get_block_id_from_height(BlockHeight::new(4)).unwrap().unwrap();
    let sentinel_block_ids = tf.create_chain_return_ids(&fork_tip_id, 1, &mut rng).unwrap();
    let sentinel_blocks: Vec<Block> =
        sentinel_block_ids.iter().map(|id| tf.block(tf.to_chain_block_id(id))).collect();
    let sentinel_block = sentinel_blocks[0].clone();
    scanner.scan_blocks(BlockHeight::new(4), sentinel_blocks).await.unwrap();

    let (name, event) = recv_event(&mut event_rx).await;
    assert_eq!(name, "block");
    assert_eq!(
        event,
        StreamEvent::Block {
            block_id: sentinel_block.get_id(),
            height: BlockHeight::new(5),
            timestamp: sentinel_block.timestamp(),
            tx_ids: sentinel_block
                .transactions()
                .iter()
                .map(|tx| tx.transaction().get_id())
                .collect(),
        },
        "unexpected sentinel event"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    match tokio::time::timeout(Duration::from_secs(3), event_rx.recv()).await {
        Err(_timed_out) => {} // no more events, as expected
        Ok(Some((name, event))) => {
            panic!("unexpected extra stream event: {name} {event:?}")
        }
        Ok(None) => panic!("the stream event collector has been closed"),
    }

    // -----------------------------------------------------------------------------------------
    // Shutdown: stop the web server and the collector. The collector is aborted as well, since
    // it would otherwise keep running indefinitely (the server keepalives prevent its internal
    // chunk timeout from firing; the terminated server connection also ends its read loop);
    // the abort does not swallow a panic that has already happened, which the join inside
    // `shutdown_webserver` propagates with the actual panic message.
    // -----------------------------------------------------------------------------------------
    shutdown_webserver(web_task).await;
    shutdown_webserver(collector_task).await;
}

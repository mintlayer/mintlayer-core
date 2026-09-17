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

//! Tests of the `/api/v2/stream` Server-Sent Events endpoint (in-memory backend).

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use api_blockchain_scanner_lib::{
    blockchain_state::BlockchainState, sync::local_state::LocalBlockchainState,
};
use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::{ApiServerStorageWrite, ApiServerTransactionRw, Transactional},
};
use api_server_common::streaming::{StreamEvent, StreamEventsChannel, TxOrigin};
use api_web_server::{
    ApiServerWebServerState, CachedValues, StreamEventsHandle, StreamingConfig, api::web_server,
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        Block, Transaction, block::timestamp::BlockTimestamp, config::create_unit_test_config,
    },
    primitives::{BlockHeight, H256, Id, Idable, time::get_time},
};
use hex::ToHex as _;
use test_utils::random::{Seed, make_seedable_rng};

use crate::DummyRPC;
use crate::test_common::{frame_data, frame_event_name};

/// The time to wait for a single expected SSE frame.
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// A minimal SSE client on top of `reqwest`, able to read raw SSE frames.
///
/// Note: `Response::chunk()` is used for reading, which does not require the `stream` feature of
/// `reqwest`.
struct SseConnection {
    response: reqwest::Response,
    buffer: String,
}

impl SseConnection {
    /// Connect to the given SSE endpoint and check the response contract.
    async fn connect(client: &reqwest::Client, url: &str) -> Self {
        let response = client.get(url).send().await.unwrap();

        assert_eq!(response.status(), 200);
        let content_type = response
            .headers()
            .get("content-type")
            .expect("content-type header must be present")
            .to_str()
            .unwrap();
        assert!(
            content_type.starts_with("text/event-stream"),
            "unexpected content-type: {content_type}"
        );
        assert_eq!(
            response
                .headers()
                .get("x-accel-buffering")
                .expect("x-accel-buffering header must be present"),
            "no"
        );

        Self {
            response,
            buffer: String::new(),
        }
    }

    /// Read the next complete SSE frame (up to the empty-line separator), failing if it doesn't
    /// arrive within `timeout`.
    async fn next_frame(&mut self, timeout: Duration) -> String {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(frame_end) = self.buffer.find("\n\n") {
                return self.buffer.drain(..frame_end + 2).collect();
            }

            let chunk = tokio::time::timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                self.response.chunk(),
            )
            .await
            .expect("timed out while waiting for an SSE frame")
            .expect("SSE request failed")
            .expect("SSE stream ended unexpectedly");

            self.buffer.push_str(std::str::from_utf8(&chunk).unwrap());
        }
    }

    /// Read the next complete SSE frame carrying a named event, skipping the non-event frames
    /// the endpoint is expected to send (the initial `retry:` directive and the keepalive
    /// comments), failing if it doesn't arrive within `timeout`.
    async fn next_event_frame(&mut self, timeout: Duration) -> String {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = self.next_frame(remaining).await;
            if frame_event_name(&frame).is_some() {
                return frame;
            }
            assert!(
                is_non_event_frame(&frame),
                "unexpected SSE frame: {frame:?}"
            );
        }
    }
}

/// Whether the frame is a non-event frame the endpoint is allowed to send: a keepalive comment
/// or an SSE `retry:` directive (the latter as the first frame of the stream, per the SSE spec).
/// Note: empty lines are frame separators rather than fields, so they are ignored.
fn is_non_event_frame(frame: &str) -> bool {
    frame
        .lines()
        .filter(|line| !line.is_empty())
        .all(|line| line.starts_with(':') || line.starts_with("retry:"))
}

/// Connect to the stream endpoint of a web server spawned on the given listener with the given
/// handle, using the default event filter.
async fn connect_to_stream(addr: std::net::SocketAddr, query: &str) -> SseConnection {
    let client = reqwest::Client::new();
    let url = format!("http://{}:{}/api/v2/stream{query}", addr.ip(), addr.port());
    SseConnection::connect(&client, &url).await
}

/// Spawn a web server on the given listener, backed by the in-memory storage and sharing the
/// given stream events handle.
fn spawn_stream_webserver(
    listener: tokio::net::TcpListener,
    stream_events: StreamEventsHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let chain_config = Arc::new(create_unit_test_config());
        let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

        let web_server_state = ApiServerWebServerState {
            db: Arc::new(storage),
            chain_config: Arc::clone(&chain_config),
            rpc: Arc::new(DummyRPC {}),
            cached_values: Arc::new(CachedValues {
                feerate_points: RwLock::new((get_time(), vec![])),
            }),
            time_getter: Default::default(),
            stream_events,
        };

        web_server(listener, web_server_state, true).await.unwrap();
    })
}

#[tokio::test]
async fn stream_endpoint_contract() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Note: the channel is cloned before being moved into the handle, so that the test can send
    // events into it.
    let channel = StreamEventsChannel::new(16);
    let handle = StreamEventsHandle::new(
        channel.clone(),
        StreamingConfig {
            keepalive_interval: Duration::from_millis(200),
            max_subscribers: 8,
        },
    );

    let task = spawn_stream_webserver(listener, handle);

    // Note: the subscription must exist before the events are sent, so the connection is opened
    // first; the response headers arriving means the endpoint has subscribed to the channel.
    let mut sse = connect_to_stream(addr, "").await;

    let tx_seen = StreamEvent::TxSeen {
        tx_id: Id::new(H256::from_low_u64_be(1)),
        origin: TxOrigin::Local,
    };
    let block = StreamEvent::Block {
        block_id: Id::new(H256::from_low_u64_be(2)),
        height: BlockHeight::new(1),
        timestamp: BlockTimestamp::from_int_seconds(1_000),
        tx_ids: vec![Id::new(H256::from_low_u64_be(3))],
    };
    let reorg = StreamEvent::Reorg {
        common_ancestor_height: BlockHeight::new(0),
        removed_block_ids: vec![Id::new(H256::from_low_u64_be(4))],
        new_tip_height: BlockHeight::new(2),
    };

    // Note: sending must succeed, since the endpoint is subscribed.
    channel.send(tx_seen.clone()).unwrap();
    channel.send(block.clone()).unwrap();
    channel.send(reorg.clone()).unwrap();

    for expected in [&tx_seen, &block, &reorg] {
        let frame = sse.next_event_frame(FRAME_TIMEOUT).await;

        assert_eq!(
            frame_event_name(&frame),
            Some(expected.event_name()),
            "unexpected SSE frame: {frame:?}"
        );

        let data = frame_data(&frame).expect("the event must carry a data field");
        assert!(
            data.starts_with('{'),
            "the data payload must be a JSON object: {data}"
        );
        let parsed: StreamEvent = serde_json::from_str(data)
            .expect("the data payload must parse back into a StreamEvent");
        assert_eq!(&parsed, expected, "event roundtrip mismatch");
    }

    // The keepalive comment must arrive when the stream is idle.
    let frame = sse.next_frame(FRAME_TIMEOUT).await;
    assert_eq!(frame.trim(), ": keepalive", "expected a keepalive comment");

    task.abort();
}

#[tokio::test]
async fn stream_types_filter() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let channel = StreamEventsChannel::new(16);
    let handle = StreamEventsHandle::new(
        channel.clone(),
        StreamingConfig {
            keepalive_interval: Duration::from_millis(200),
            max_subscribers: 8,
        },
    );

    let task = spawn_stream_webserver(listener, handle);

    let mut sse = connect_to_stream(addr, "?types=block").await;

    let tx_seen = StreamEvent::TxSeen {
        tx_id: Id::new(H256::from_low_u64_be(10)),
        origin: TxOrigin::Remote,
    };
    let block = StreamEvent::Block {
        block_id: Id::new(H256::from_low_u64_be(11)),
        height: BlockHeight::new(1),
        timestamp: BlockTimestamp::from_int_seconds(2_000),
        tx_ids: vec![],
    };

    channel.send(tx_seen.clone()).unwrap();
    channel.send(block.clone()).unwrap();

    // The block event must arrive (possibly preceded by keepalive comments and the initial
    // `retry:` directive).
    let frame = sse.next_event_frame(FRAME_TIMEOUT).await;
    assert_eq!(
        frame_event_name(&frame),
        Some("block"),
        "unexpected event instead of the block event: {frame:?}"
    );

    // No tx_seen event must ever arrive within the window after the block event. Keepalive
    // comments are allowed to arrive.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, sse.next_frame(FRAME_TIMEOUT)).await {
            Err(_elapsed) => break, // the observation window is over
            Ok(frame) => assert_ne!(
                frame_event_name(&frame),
                Some("tx_seen"),
                "tx_seen must not be delivered to a block-only subscription"
            ),
        }
    }

    // An invalid event type must be rejected.
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}:{}/api/v2/stream?types=bogus",
            addr.ip(),
            addr.port()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    task.abort();
}

/// A block event must refer to block data that is queryable through the regular REST endpoint.
#[tokio::test]
async fn stream_block_event_is_queryable() {
    let mut rng = make_seedable_rng(Seed::from_entropy());
    let mut tf = TestFramework::builder(&mut rng).build();
    let chain_config = tf.chain_config().clone();

    let block_ids = tf
        .create_chain_return_ids(&chain_config.genesis_block_id(), 2, &mut rng)
        .unwrap();
    let blocks: Vec<Block> =
        block_ids.iter().map(|id| tf.block(tf.to_chain_block_id(id))).collect();

    // Scan the blocks into the in-memory storage through the real scanner. Note: the in-memory
    // backend drops stream events, so the event is sent through the channel manually below.
    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);
        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();
        storage
    };
    let mut scanner = BlockchainState::new(chain_config.clone(), storage);
    scanner.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();
    scanner.scan_blocks(BlockHeight::new(0), blocks.clone()).await.unwrap();

    let scanned_block = blocks[0].clone();
    let block_id = scanned_block.get_id();
    let tx_ids: Vec<Id<Transaction>> = scanned_block
        .transactions()
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let channel = StreamEventsChannel::new(16);
    let handle = StreamEventsHandle::new(
        channel.clone(),
        StreamingConfig {
            keepalive_interval: Duration::from_millis(200),
            max_subscribers: 8,
        },
    );

    let web_storage = scanner.storage().clone_storage().await;
    let task = tokio::spawn(async move {
        let web_server_state = ApiServerWebServerState {
            db: Arc::new(web_storage),
            chain_config,
            rpc: Arc::new(DummyRPC {}),
            cached_values: Arc::new(CachedValues {
                feerate_points: RwLock::new((get_time(), vec![])),
            }),
            time_getter: Default::default(),
            stream_events: handle,
        };

        web_server(listener, web_server_state, true).await.unwrap();
    });

    let mut sse = connect_to_stream(addr, "").await;

    // This is the event the scanner would have emitted for the scanned block.
    let event = StreamEvent::Block {
        block_id,
        height: BlockHeight::new(1),
        timestamp: scanned_block.timestamp(),
        tx_ids: tx_ids.clone(),
    };
    channel.send(event.clone()).unwrap();

    let frame = sse.next_event_frame(FRAME_TIMEOUT).await;
    assert_eq!(frame_event_name(&frame), Some("block"));
    let data = frame_data(&frame).expect("the block event must carry a data field");
    let parsed: StreamEvent = serde_json::from_str(data).unwrap();
    assert_eq!(parsed, event);

    // The event data must be immediately queryable through the REST endpoint.
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}:{}/api/v2/block/{}",
            addr.ip(),
            addr.port(),
            block_id.to_hash().encode_hex::<String>()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    let served_tx_ids: Vec<&str> = body["body"]["transactions"]
        .as_array()
        .expect("transactions must be an array")
        .iter()
        .map(|tx| tx["id"].as_str().expect("tx id must be a string"))
        .collect();
    let expected_tx_ids: Vec<String> =
        tx_ids.iter().map(|tx_id| tx_id.to_hash().encode_hex::<String>()).collect();
    assert_eq!(served_tx_ids, expected_tx_ids);

    task.abort();
}

/// The subscriber limit must be enforced, and the slot must be released on client disconnect, so
/// that a new subscriber is accepted and is fully functional.
#[tokio::test]
async fn stream_subscriber_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Note: the channel is cloned before being moved into the handle, so that the test can send
    // events into it.
    let channel = StreamEventsChannel::new(16);
    let handle = StreamEventsHandle::new(
        channel.clone(),
        StreamingConfig {
            keepalive_interval: Duration::from_millis(200),
            max_subscribers: 1,
        },
    );

    let task = spawn_stream_webserver(listener, handle);

    // Take the only subscriber slot.
    let first = connect_to_stream(addr, "").await;

    // With the slot taken, another subscriber must be rejected.
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}:{}/api/v2/stream",
            addr.ip(),
            addr.port()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);
    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"error": "Too many concurrent stream connections"})
    );

    // Once the first client disconnects, the slot must be released, so that a new subscriber is
    // accepted again. Note: the server notices the disconnect asynchronously, hence the retry
    // loop.
    drop(first);
    let mut second = {
        let url = format!("http://{}:{}/api/v2/stream", addr.ip(), addr.port());
        let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
        loop {
            let response = client.get(url.as_str()).send().await.unwrap();
            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the subscriber slot was not released on client disconnect"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }

            assert_eq!(response.status(), 200);
            let content_type = response
                .headers()
                .get("content-type")
                .expect("content-type header must be present")
                .to_str()
                .unwrap();
            assert!(
                content_type.starts_with("text/event-stream"),
                "unexpected content-type: {content_type}"
            );

            break SseConnection {
                response,
                buffer: String::new(),
            };
        }
    };

    let tx_seen = StreamEvent::TxSeen {
        tx_id: Id::new(H256::from_low_u64_be(20)),
        origin: TxOrigin::Local,
    };
    let block = StreamEvent::Block {
        block_id: Id::new(H256::from_low_u64_be(21)),
        height: BlockHeight::new(1),
        timestamp: BlockTimestamp::from_int_seconds(3_000),
        tx_ids: vec![Id::new(H256::from_low_u64_be(22))],
    };

    // Note: sending must succeed, since the endpoint is subscribed.
    channel.send(tx_seen.clone()).unwrap();
    channel.send(block.clone()).unwrap();

    // The events sent after the reconnection must be delivered to the new subscriber.
    for expected in [&tx_seen, &block] {
        let frame = second.next_event_frame(FRAME_TIMEOUT).await;

        assert_eq!(
            frame_event_name(&frame),
            Some(expected.event_name()),
            "unexpected SSE frame: {frame:?}"
        );

        let data = frame_data(&frame).expect("the event must carry a data field");
        let parsed: StreamEvent = serde_json::from_str(data)
            .expect("the data payload must parse back into a StreamEvent");
        assert_eq!(&parsed, expected, "event roundtrip mismatch");
    }

    task.abort();
}

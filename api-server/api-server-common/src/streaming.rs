// Copyright (c) 2026 RBB S.r.l
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

//! Real-time event streaming for block explorer clients.
//!
//! Events are produced by two independent sources:
//! * the scanner subsystem appends [StreamEvent::Block] and [StreamEvent::Reorg] events to the
//!   storage *inside* the same database transaction that performs the indexing work, so once an
//!   event is committed, the data it refers to is immediately queryable through the regular REST
//!   endpoints;
//! * the web server bridges mempool events from the node's WebSocket RPC into
//!   [StreamEvent::TxSeen] events.
//!
//! The Postgres backend additionally issues a `pg_notify` wakeup after the transaction commits,
//! which the web server uses to promptly drain new events and forward them to all connected
//! stream subscribers. Event payloads travel in the `ml.emitted_events` table and are only
//! referenced by the notification, because `pg_notify` payloads are capped at 8000 bytes.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use common::{
    chain::{Block, Transaction, block::timestamp::BlockTimestamp},
    primitives::{BlockHeight, Id},
};
use serde::{Deserialize, Serialize};

/// The name of the Postgres notification channel used as a commit wakeup ping.
pub const STREAM_EVENTS_NOTIFY_CHANNEL: &str = "mintlayer_events";

/// Monotonic identifier of a stream event, as assigned by the storage backend.
pub type StreamEventId = i64;

/// The maximum number of stream events the event pump reads per database round trip, keeping the
/// memory use of the pump bounded regardless of the backlog size.
pub const STREAM_EVENTS_READ_BATCH_SIZE: i64 = 1000;

/// The number of the most recent stream events the storage backend retains; older events are
/// pruned, since the stream endpoint does not support replays anyway.
pub const STREAM_EVENTS_RETENTION_COUNT: i64 = 10_000;

/// The simplified origin of a transaction seen in the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxOrigin {
    Local,
    Remote,
}

/// An event that is streamed to block explorer clients.
///
/// The payloads are intentionally kept small; the explorer is expected to hydrate the details
/// through the regular REST endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum StreamEvent {
    /// A transaction reached the node's mempool.
    TxSeen {
        tx_id: Id<Transaction>,
        origin: TxOrigin,
    },
    /// A block has been fully indexed into the api-server database.
    Block {
        block_id: Id<Block>,
        height: BlockHeight,
        timestamp: BlockTimestamp,
        tx_ids: Vec<Id<Transaction>>,
    },
    /// Previously indexed blocks have been disconnected after a chain reorganization.
    Reorg {
        common_ancestor_height: BlockHeight,
        removed_block_ids: Vec<Id<Block>>,
        new_tip_height: BlockHeight,
    },
}

impl StreamEvent {
    /// The kind of the event.
    pub fn event_type(&self) -> StreamEventType {
        match self {
            StreamEvent::TxSeen { .. } => StreamEventType::TxSeen,
            StreamEvent::Block { .. } => StreamEventType::Block,
            StreamEvent::Reorg { .. } => StreamEventType::Reorg,
        }
    }

    /// The name of the event as used in the Server-Sent Events protocol, so that clients can
    /// subscribe to specific event kinds with `EventSource.addEventListener(name, ...)`.
    pub fn event_name(&self) -> &'static str {
        self.event_type().name()
    }
}

/// The kinds of the stream events; the single source of truth for the event names used in the
/// Server-Sent Events protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StreamEventType {
    TxSeen,
    Block,
    Reorg,
}

impl StreamEventType {
    /// All the event kinds, in a stable order.
    pub const ALL: &'static [StreamEventType] = &[Self::TxSeen, Self::Block, Self::Reorg];

    /// The name of the event kind as used in the Server-Sent Events protocol.
    pub fn name(self) -> &'static str {
        match self {
            StreamEventType::TxSeen => "tx_seen",
            StreamEventType::Block => "block",
            StreamEventType::Reorg => "reorg",
        }
    }
}

impl fmt::Display for StreamEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for StreamEventType {
    type Err = StreamEventTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.name() == s)
            .ok_or(StreamEventTypeParseError)
    }
}

/// The error returned when a string does not name a valid [StreamEventType].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEventTypeParseError;

impl fmt::Display for StreamEventTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid stream event type, expected one of: {}",
            StreamEventType::ALL
                .iter()
                .map(|kind| kind.name())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// The error returned when reading the stream events from the source fails.
#[derive(Debug, thiserror::Error)]
#[error("Failed to read stream events: {0}")]
pub struct StreamEventReadError(pub String);

/// A cloneable handle for distributing stream events to subscribers.
#[derive(Clone)]
pub struct StreamEventsChannel {
    sender: Arc<tokio::sync::broadcast::Sender<StreamEvent>>,
}

impl StreamEventsChannel {
    /// Create a channel that can buffer up to `capacity` events per subscriber.
    pub fn new(capacity: usize) -> Self {
        let (sender, _receiver) = tokio::sync::broadcast::channel(capacity);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Subscribe to the stream events. Each subscriber receives the events sent after the
    /// subscription has been created.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<StreamEvent> {
        self.sender.subscribe()
    }

    /// Send an event to all subscribers. Returns `Err` only if there are no subscribers.
    pub fn send(
        &self,
        event: StreamEvent,
    ) -> Result<(), tokio::sync::broadcast::error::SendError<StreamEvent>> {
        self.sender.send(event).map(|_| ())
    }
}

/// The source of the stream events for the [event pump][run_event_pump].
///
/// The wait-and-poll behavior is abstracted away so that the pump logic itself (backlog draining,
/// resume from the last seen id) can be tested independently of the database backend.
#[async_trait::async_trait]
pub trait StreamEventSource: Send {
    /// Wait until new events may be available. This is caused either by a database notification
    /// or by the periodic poll timeout elapsing.
    async fn wait_for_wakeup(&mut self);

    /// Read the events with an id greater than `last_seen_id`, in ascending id order.
    async fn read_events_after(
        &mut self,
        last_seen_id: StreamEventId,
    ) -> Result<Vec<(StreamEventId, StreamEvent)>, StreamEventReadError>;
}

/// The event pump: forwards stream events from a [StreamEventSource] into a
/// [StreamEventsChannel], tracking the id of the last forwarded event.
///
/// The backlog is drained in batches before waiting for the next wakeup, which also takes care of
/// draining whatever was committed before this pump was started.
pub async fn run_event_pump(
    mut source: impl StreamEventSource,
    channel: StreamEventsChannel,
    mut last_seen_id: StreamEventId,
) {
    loop {
        // Note: a full batch hints at more events being available, in which case the next batch
        // is read immediately; this keeps the memory use of the pump bounded while large backlogs
        // are forwarded without waiting for the next wakeup.
        loop {
            match source.read_events_after(last_seen_id).await {
                Ok(events) => {
                    let batch_size = events.len() as i64;
                    for (event_id, event) in events {
                        logging::log::debug!(
                            "Streaming event #{event_id} ({})",
                            event.event_name(),
                        );
                        // Note: sending may fail when there are no subscribers; this is not an
                        // error, the events are persisted and can still be read later.
                        let _ = channel.send(event);
                        last_seen_id = event_id;
                    }
                    if batch_size < STREAM_EVENTS_READ_BATCH_SIZE {
                        break;
                    }
                }
                Err(err) => {
                    logging::log::error!("{err}");
                    break;
                }
            }
        }

        source.wait_for_wakeup().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use common::primitives::H256;

    fn test_block_event(height: u64) -> StreamEvent {
        StreamEvent::Block {
            block_id: Id::new(H256::from_low_u64_be(height)),
            height: BlockHeight::new(height),
            timestamp: BlockTimestamp::from_int_seconds(1_000_000 + height),
            tx_ids: vec![Id::new(H256::from_low_u64_be(1000 + height))],
        }
    }

    fn test_reorg_event(height: u64) -> StreamEvent {
        StreamEvent::Reorg {
            common_ancestor_height: BlockHeight::new(height),
            removed_block_ids: vec![Id::new(H256::from_low_u64_be(2000 + height))],
            new_tip_height: BlockHeight::new(height + 1),
        }
    }

    /// A source that yields pre-scripted events, one batch per wakeup.
    struct FakeSource {
        batches: std::sync::Mutex<std::sync::mpsc::Receiver<Vec<(StreamEventId, StreamEvent)>>>,
        notify_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
    }

    impl FakeSource {
        fn new() -> FakeSourceParts {
            let (batch_tx, batch_rx) = std::sync::mpsc::channel();
            let (notify_tx, notify_rx) = tokio::sync::mpsc::unbounded_channel();
            (
                Self {
                    batches: std::sync::Mutex::new(batch_rx),
                    notify_rx,
                },
                batch_tx,
                notify_tx,
            )
        }
    }

    type FakeEventBatch = Vec<(StreamEventId, StreamEvent)>;

    type FakeSourceParts = (
        FakeSource,
        std::sync::mpsc::Sender<FakeEventBatch>,
        tokio::sync::mpsc::UnboundedSender<()>,
    );

    #[async_trait::async_trait]
    impl StreamEventSource for FakeSource {
        async fn wait_for_wakeup(&mut self) {
            // Note: the pump calls this after each read, so the test must not block forever if
            // there are no more notifications; hence the short timeout.
            let _ = tokio::time::timeout(Duration::from_millis(100), self.notify_rx.recv()).await;
        }

        async fn read_events_after(
            &mut self,
            last_seen_id: StreamEventId,
        ) -> Result<Vec<(StreamEventId, StreamEvent)>, StreamEventReadError> {
            let batch = self.batches.lock().unwrap().try_recv().ok().unwrap_or_default();
            Ok(batch.into_iter().filter(|(id, _)| *id > last_seen_id).collect())
        }
    }

    #[tokio::test]
    async fn pump_drains_backlog_and_resumes_from_last_seen_id() {
        let (source, batch_tx, notify_tx) = FakeSource::new();
        let channel = StreamEventsChannel::new(16);
        let mut rx = channel.subscribe();

        let pump = tokio::spawn(run_event_pump(source, channel.clone(), 0));

        // Note: the backlog, committed before the pump even saw the wakeup.
        batch_tx.send(vec![(1, test_block_event(1)), (2, test_block_event(2))]).unwrap();
        notify_tx.send(()).unwrap();

        assert_eq!(rx.recv().await.unwrap(), test_block_event(1));
        assert_eq!(rx.recv().await.unwrap(), test_block_event(2));

        // A new batch is forwarded and the previously seen ids are not re-sent.
        batch_tx.send(vec![(2, test_block_event(2)), (3, test_reorg_event(2))]).unwrap();
        notify_tx.send(()).unwrap();

        assert_eq!(rx.recv().await.unwrap(), test_reorg_event(2));

        pump.abort();
    }

    #[tokio::test]
    async fn pump_keeps_running_after_read_errors() {
        struct FailingSource {
            failing: bool,
        }

        #[async_trait::async_trait]
        impl StreamEventSource for FailingSource {
            async fn wait_for_wakeup(&mut self) {
                // Note: without this, the pump would spin without ever yielding on a
                // single-threaded runtime.
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            async fn read_events_after(
                &mut self,
                _last_seen_id: StreamEventId,
            ) -> Result<Vec<(StreamEventId, StreamEvent)>, StreamEventReadError> {
                if self.failing {
                    self.failing = false;
                    Err(StreamEventReadError("storage error".to_owned()))
                } else {
                    self.failing = true;
                    Ok(vec![(7, test_block_event(7))])
                }
            }
        }

        let channel = StreamEventsChannel::new(16);
        let mut rx = channel.subscribe();
        let pump = tokio::spawn(run_event_pump(FailingSource { failing: false }, channel, 0));

        assert_eq!(rx.recv().await.unwrap(), test_block_event(7));
        // Note: the pump survives the error and keeps polling.
        assert_eq!(rx.recv().await.unwrap(), test_block_event(7));

        pump.abort();
    }

    #[test]
    fn event_serde_roundtrip() {
        let events = [
            StreamEvent::TxSeen {
                tx_id: Id::new(H256::from_low_u64_be(1)),
                origin: TxOrigin::Remote,
            },
            test_block_event(3),
            test_reorg_event(2),
        ];

        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: StreamEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, event);
        }
    }

    #[test]
    fn event_names() {
        assert_eq!(
            StreamEvent::TxSeen {
                tx_id: Id::new(H256::zero()),
                origin: TxOrigin::Local,
            }
            .event_name(),
            "tx_seen"
        );
        assert_eq!(test_block_event(0).event_name(), "block");
        assert_eq!(test_reorg_event(0).event_name(), "reorg");
    }
}

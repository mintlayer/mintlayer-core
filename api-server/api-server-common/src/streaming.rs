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
use std::time::Duration;

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
///
/// Note: the pruning is based on the consumption progress of the event pump (see
/// [`StreamEventSource::update_consumed_id`]), so that unread events are never deleted.
pub const STREAM_EVENTS_RETENTION_COUNT: i64 = 10_000;

/// The absolute upper bound on the number of retained stream events, as a multiple of
/// [`STREAM_EVENTS_RETENTION_COUNT`].
///
/// Note: without this bound, a prolonged outage of the event pump (e.g. the web server being
/// down while the scanner keeps indexing) would grow the event log without limit, since the
/// pruning waits for the pump to catch up. When this bound kicks in, unread events are lost,
/// which is logged loudly by the pruning.
pub const STREAM_EVENTS_RETENTION_HARD_LIMIT_FACTOR: i64 = 10;

/// The key under which the event pump consumption progress is stored in the database.
pub const STREAM_EVENTS_PUMP_CURSOR_KEY: &str = "stream_events_pump_cursor";

/// How many real-time stream events may be buffered per connected client before the client
/// receives a `lag` advisory event instead of the missed events.
pub const DEFAULT_STREAM_EVENTS_BROADCAST_CAPACITY: usize = 1024;

/// The default maximum number of concurrently served stream (SSE) connections.
///
/// Note: each stream connection holds per-connection state (a broadcast receiver and a stream
/// task) for an unbounded lifetime, so the number of connections must be bounded; a reverse
/// proxy in front of the server may impose its own limits as well.
pub const DEFAULT_STREAM_EVENTS_MAX_SUBSCRIBERS: usize = 128;

/// How often the database event pump polls for new events as a safety net for missed
/// notifications.
pub const DEFAULT_STREAM_EVENTS_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// How often a keepalive comment is sent to connected stream clients.
pub const DEFAULT_STREAM_EVENTS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

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
    /// Advisory that a gap in the stream is possible: `skipped` events are known to have been
    /// missed (zero when the size of the gap is unknown, e.g. when the mempool bridge was
    /// disconnected from the node). The missed events cannot be replayed (the stream has no
    /// replay semantics), so clients should reconcile through the regular REST endpoints.
    Lag { skipped: u64 },
}

impl StreamEvent {
    /// The kind of the event.
    pub fn event_type(&self) -> StreamEventType {
        match self {
            StreamEvent::TxSeen { .. } => StreamEventType::TxSeen,
            StreamEvent::Block { .. } => StreamEventType::Block,
            StreamEvent::Reorg { .. } => StreamEventType::Reorg,
            StreamEvent::Lag { .. } => StreamEventType::Lag,
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
    Lag,
}

impl StreamEventType {
    /// All the event kinds, in a stable order.
    pub const ALL: &'static [StreamEventType] =
        &[Self::TxSeen, Self::Block, Self::Reorg, Self::Lag];

    /// The name of the event kind as used in the Server-Sent Events protocol.
    pub fn name(self) -> &'static str {
        match self {
            StreamEventType::TxSeen => "tx_seen",
            StreamEventType::Block => "block",
            StreamEventType::Reorg => "reorg",
            StreamEventType::Lag => "lag",
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
pub enum StreamEventReadError {
    #[error("Failed to read stream events: {0}")]
    Other(String),
    /// A committed event row cannot be decoded; the pump skips the event (loudly) instead of
    /// being permanently stalled by it.
    #[error("stream event #{id} cannot be decoded: {error}")]
    UndecodableEvent { id: StreamEventId, error: String },
}

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
    ///
    /// Note: a subscriber that falls more than `capacity` events behind receives a
    /// `broadcast::error::RecvError::Lagged` on the next receive and the skipped events are lost
    /// permanently; the stream has no replay semantics.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<StreamEvent> {
        self.sender.subscribe()
    }

    /// Send an event to all subscribers. Returns `Err` only if there are no subscribers.
    ///
    /// Note: a subscriber that fell too far behind silently misses the events that no longer
    /// fit into its per-subscriber buffer (surfaced to that subscriber as a `lag` advisory
    /// event when it next receives).
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

    /// Record that the pump has consumed all events up to `last_seen_id`.
    ///
    /// Note: the retention pruning in the database uses the recorded progress to never delete
    /// events that have not been pumped yet; backends that don't need it do nothing.
    async fn update_consumed_id(&mut self, _last_seen_id: StreamEventId) {}

    /// The event id to start streaming from.
    ///
    /// Note: backends that support stream events return the id of the most recent event, so that
    /// the events committed before this pump was started are not re-broadcast to the currently
    /// connected clients as if they were fresh (the stream has no replay semantics).
    async fn initial_last_seen_id(&mut self) -> StreamEventId {
        0
    }
}

/// The event pump: forwards stream events from a [StreamEventSource] into a
/// [StreamEventsChannel], tracking the id of the last forwarded event.
///
/// Note: the pump runs for the whole lifetime of the process; there is no graceful shutdown
/// path. The server brings the process down if the pump task ever terminates (see the
/// supervisor in the web server binary), which is also how the web server itself is terminated.
pub async fn run_event_pump(
    mut source: impl StreamEventSource,
    channel: StreamEventsChannel,
    mut last_seen_id: StreamEventId,
) {
    logging::log::info!("Streaming events after #{last_seen_id}");
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
                    if batch_size > 0 {
                        // Note: the consumption progress is recorded so that the retention
                        // pruning in the database never deletes events that have not been
                        // pumped (and thus broadcast) yet.
                        source.update_consumed_id(last_seen_id).await;
                    }
                    if batch_size < STREAM_EVENTS_READ_BATCH_SIZE {
                        break;
                    }
                }
                // Note: an undecodable event is skipped instead of stalling the whole stream:
                // the row is logged loudly and the clients are told about the gap through a
                // `lag` advisory, but a single corrupted row must not block every other event
                // (including reorg notices) indefinitely.
                Err(StreamEventReadError::UndecodableEvent { id, error: err }) => {
                    logging::log::error!(
                        "Skipping stream event #{id} ({err}); clients are notified via a lag \
                        advisory and can recover through the REST endpoints"
                    );
                    let _ = channel.send(StreamEvent::Lag { skipped: 1 });
                    last_seen_id = id;
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
                    Err(StreamEventReadError::Other("storage error".to_owned()))
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

    #[tokio::test]
    async fn pump_skips_undecodable_events_with_lag_advisory() {
        struct CorruptedRowSource {
            served: bool,
        }

        #[async_trait::async_trait]
        impl StreamEventSource for CorruptedRowSource {
            async fn wait_for_wakeup(&mut self) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            async fn read_events_after(
                &mut self,
                last_seen_id: StreamEventId,
            ) -> Result<Vec<(StreamEventId, StreamEvent)>, StreamEventReadError> {
                if last_seen_id == 0 {
                    // The id is returned in the error so the pump can advance past the row.
                    Err(StreamEventReadError::UndecodableEvent {
                        id: 5,
                        error: "bad payload".to_owned(),
                    })
                } else if !self.served {
                    self.served = true;
                    Ok(vec![(7, test_block_event(7))])
                } else {
                    Ok(vec![])
                }
            }
        }

        let channel = StreamEventsChannel::new(16);
        let mut rx = channel.subscribe();
        let pump = tokio::spawn(run_event_pump(
            CorruptedRowSource { served: false },
            channel,
            0,
        ));

        // The gap advisory for the skipped event arrives first, then the stream continues
        // with the events after the corrupted row.
        assert_eq!(rx.recv().await.unwrap(), StreamEvent::Lag { skipped: 1 });
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
            StreamEvent::Lag { skipped: 4 },
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
        assert_eq!(StreamEvent::Lag { skipped: 0 }.event_name(), "lag");
    }
}

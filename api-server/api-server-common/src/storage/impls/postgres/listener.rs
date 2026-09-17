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

//! Postgres LISTEN/NOTIFY based wakeup source for the stream event pump.

use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use tokio_postgres::AsyncMessage;

use crate::streaming::{
    STREAM_EVENTS_NOTIFY_CHANNEL, STREAM_EVENTS_PUMP_CURSOR_KEY, StreamEvent, StreamEventId,
    StreamEventReadError, StreamEventSource,
};

use super::TransactionalApiServerPostgresStorage;
use crate::storage::storage_api::{ApiServerStorageError, ApiServerStorageRead, Transactional};

/// The upper bound of the retry delay of the initial event id read.
const MAX_INITIAL_ID_RETRY_DELAY: Duration = Duration::from_secs(60);

/// A dedicated Postgres connection that listens for stream event notifications.
///
/// Note: Postgres only delivers notifications on the connection that issued `LISTEN`, so this
/// connection cannot be taken from the connection pool.
pub struct PostgresEventListener {
    /// Note: the connection stays alive as long as the client is not dropped; dropping the client
    /// also terminates the driver task.
    _client: tokio_postgres::Client,
    _driver: tokio::task::JoinHandle<()>,
    wakeups_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
}

impl PostgresEventListener {
    /// Wait for the next notification wakeup; `None` means the connection is no longer alive.
    pub async fn recv(&mut self) -> Option<()> {
        self.wakeups_rx.recv().await
    }
}

/// The production [StreamEventSource]: wakes up on database notifications, with a periodic poll
/// as a safety net for missed notifications, and reads the new events through the regular
/// read-only storage transactions.
pub struct PostgresStreamEventSource {
    storage: Arc<TransactionalApiServerPostgresStorage>,
    listener: PostgresEventListener,
    poll_interval: Duration,
}

impl PostgresStreamEventSource {
    pub fn new(
        storage: Arc<TransactionalApiServerPostgresStorage>,
        listener: PostgresEventListener,
        poll_interval: Duration,
    ) -> Self {
        Self {
            storage,
            listener,
            poll_interval,
        }
    }

    /// Re-establish the listener connection, bounded by the poll interval so that a slow or
    /// failing database cannot stall the pump for long.
    async fn reconnect(&mut self) -> Result<(), ApiServerStorageError> {
        let listener = tokio::time::timeout(self.poll_interval, self.storage.new_event_listener())
            .await
            .map_err(|_| {
                ApiServerStorageError::InitializationError(
                    "Stream event listener reconnection timed out".to_owned(),
                )
            })??;

        logging::log::info!("Stream event listener connection re-established");
        self.listener = listener;
        Ok(())
    }

    /// The id of the most recently committed stream event.
    async fn latest_event_id(&self) -> Result<StreamEventId, ApiServerStorageError> {
        let db_tx = self.storage.transaction_ro().await?;
        // Note: the events table is empty right after initialization.
        Ok(db_tx.latest_stream_event_id().await?.unwrap_or(0))
    }
}

#[async_trait::async_trait]
impl StreamEventSource for PostgresStreamEventSource {
    async fn wait_for_wakeup(&mut self) {
        tokio::select! {
            // Note: the pump keeps track of the last seen id itself, so the notification is just
            // a wakeup signal.
            wakeup = self.listener.recv() => {
                if wakeup.is_none() {
                    // Note: the listener connection is dead; without the reconnect below, the
                    // pump would fall back to pure polling forever and the notifications would
                    // never be received again.
                    if self.reconnect().await.is_err() {
                        tokio::time::sleep(self.poll_interval).await;
                    }
                }
            }
            _ = tokio::time::sleep(self.poll_interval) => {}
        }
    }

    async fn read_events_after(
        &mut self,
        last_seen_id: StreamEventId,
    ) -> Result<Vec<(StreamEventId, StreamEvent)>, StreamEventReadError> {
        let db_tx = self
            .storage
            .transaction_ro()
            .await
            .map_err(|e: ApiServerStorageError| StreamEventReadError(e.to_string()))?;
        db_tx
            .read_stream_events_after(last_seen_id)
            .await
            .map_err(|e| StreamEventReadError(e.to_string()))
    }

    async fn initial_last_seen_id(&mut self) -> StreamEventId {
        // Note: an iterative retry loop is used instead of a recursive call, so that a prolonged
        // database outage cannot build an unbounded chain of pinned futures. The delay grows
        // exponentially (up to the reconnection timeout used elsewhere in this source) so that a
        // dead database does not spin the pump silently.
        let mut delay = self.poll_interval;
        loop {
            match self.latest_event_id().await {
                Ok(last_event_id) => return last_event_id,
                Err(err) => {
                    // Note: falling back to zero would re-broadcast old events to the currently
                    // connected clients, so the failure is retried until the database answers.
                    logging::log::error!("Failed to read the latest stream event id: {err}");
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, MAX_INITIAL_ID_RETRY_DELAY);
                }
            }
        }
    }

    async fn update_consumed_id(&mut self, last_seen_id: StreamEventId) {
        if let Err(err) = self.storage.update_stream_events_pump_cursor(last_seen_id).await {
            // Note: a failed cursor update is not fatal; the pruning falls back to the plain
            // retention window and the cursor is refreshed on the next batch.
            logging::log::warn!("Failed to record the stream event consumption progress: {err}");
        }
    }
}

impl TransactionalApiServerPostgresStorage {
    /// Record the stream event consumption progress of the event pump.
    ///
    /// Note: the retention pruning never deletes the events above the recorded cursor, so that
    /// a lagging pump cannot lose unread events to pruning. The stored value is only ever
    /// advanced, even when multiple pumps write to the same database.
    pub async fn update_stream_events_pump_cursor(
        &self,
        last_seen_id: StreamEventId,
    ) -> Result<(), ApiServerStorageError> {
        // Note: a dedicated connection (autocommit) is used, because the pump only holds an
        // Arc of the storage, which cannot start a read-write transaction; the single-statement
        // upsert is atomic on its own.
        let connection = self
            .pool
            .get()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        connection
            .execute(
                "INSERT INTO ml.misc_data (name, value) VALUES ($1, $2)
                    ON CONFLICT (name)
                    DO UPDATE SET value = GREATEST(ml.misc_data.value, EXCLUDED.value);",
                &[&STREAM_EVENTS_PUMP_CURSOR_KEY, &last_seen_id.to_be_bytes().to_vec()],
            )
            .await
            .map(|_| ())
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))
    }

    /// Create a dedicated connection that listens for stream event notifications.
    pub async fn new_event_listener(&self) -> Result<PostgresEventListener, ApiServerStorageError> {
        let (client, mut connection) =
            self.connection_config.connect(tokio_postgres::NoTls).await.map_err(|e| {
                ApiServerStorageError::InitializationError(format!(
                    "Stream event listener connection failed: {e}"
                ))
            })?;

        let (wakeups_tx, wakeups_rx) = tokio::sync::mpsc::unbounded_channel();

        // Note: the connection driver task must be spawned before issuing any queries, because
        // the client only queues the requests and the driver is the one that performs them.
        let driver = tokio::spawn(async move {
            // Note: the stream of messages ends when the connection is closed, e.g. when the
            // client is dropped.
            loop {
                match poll_fn(|cx| connection.poll_message(cx)).await {
                    // Note: the notification payload (the id of the last emitted event) is
                    // intentionally ignored; the pump keeps track of the last seen id itself.
                    Some(Ok(AsyncMessage::Notification(_))) => {
                        let _ = wakeups_tx.send(());
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        logging::log::error!("Stream event listener connection error: {err}");
                        break;
                    }
                    None => break,
                }
            }
        });

        client
            .batch_execute(&format!("LISTEN {STREAM_EVENTS_NOTIFY_CHANNEL};"))
            .await
            .map_err(|e| {
                ApiServerStorageError::InitializationError(format!(
                    "Stream event listener setup failed: {e}"
                ))
            })?;

        Ok(PostgresEventListener {
            _client: client,
            _driver: driver,
            wakeups_rx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The listener and the event source are exercised by the postgres backend test suite and the
    // stack tests, which require a real database.
    #[test]
    fn notify_channel_name_is_stable() {
        assert_eq!(STREAM_EVENTS_NOTIFY_CHANNEL, "mintlayer_events");
    }
}

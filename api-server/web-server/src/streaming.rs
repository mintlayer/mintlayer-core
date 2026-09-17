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

//! Real-time event streaming support: the stream event channel handle used by the web server
//! state, the database event pump, and the bridge from the node's mempool events.

use std::sync::Arc;
use std::time::Duration;

use api_server_common::streaming::{
    StreamEvent, StreamEventSource, StreamEventsChannel, TxOrigin, run_event_pump,
};
use mempool::rpc::MempoolRpcClient;
use mempool::rpc_event::{RpcEvent, RpcTxOrigin};
use node_comm::rpc_client::NodeRpcClient;

/// How many real-time stream events may be buffered per connected client before the client
/// receives a `lag` advisory event instead of the missed events.
pub const DEFAULT_STREAM_EVENTS_BROADCAST_CAPACITY: usize = 1024;

/// How often the database event pump polls for new events as a safety net for missed
/// notifications.
pub const DEFAULT_STREAM_EVENTS_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// How often a keepalive comment is sent to connected stream clients.
pub const DEFAULT_STREAM_EVENTS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// The default maximum number of concurrently served stream (SSE) connections.
///
/// Note: each stream connection holds per-connection state (a broadcast receiver and a stream
/// task) for an unbounded lifetime, so the number of connections must be bounded; a reverse
/// proxy in front of the server may impose its own limits as well.
pub const DEFAULT_STREAM_EVENTS_MAX_SUBSCRIBERS: usize = 128;

/// How long to wait for the mempool WebSocket subscription to be established before giving up
/// and retrying (with backoff).
const MEMPOOL_SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait before the first re-attempt of the subscription to the node's mempool events
/// after it has been lost. The delay doubles on every failed attempt, up to
/// [`MEMPOOL_RESUBSCRIBE_DELAY_MAX`].
const MEMPOOL_RESUBSCRIBE_DELAY: Duration = Duration::from_secs(1);

/// The upper bound of the mempool subscription retry delay.
const MEMPOOL_RESUBSCRIBE_DELAY_MAX: Duration = Duration::from_secs(60);

/// Streaming-related configuration of the web server.
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    pub keepalive_interval: Duration,
    pub max_subscribers: usize,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: DEFAULT_STREAM_EVENTS_KEEPALIVE_INTERVAL,
            max_subscribers: DEFAULT_STREAM_EVENTS_MAX_SUBSCRIBERS,
        }
    }
}

/// The stream event channel and its configuration, as stored in the web server state.
#[derive(Clone)]
pub struct StreamEventsHandle {
    pub channel: StreamEventsChannel,
    pub config: StreamingConfig,
    subscriber_slots: Arc<tokio::sync::Semaphore>,
}

impl Default for StreamEventsHandle {
    fn default() -> Self {
        Self::new(
            StreamEventsChannel::new(DEFAULT_STREAM_EVENTS_BROADCAST_CAPACITY),
            StreamingConfig::default(),
        )
    }
}

impl StreamEventsHandle {
    pub fn new(channel: StreamEventsChannel, config: StreamingConfig) -> Self {
        Self {
            channel,
            subscriber_slots: Arc::new(tokio::sync::Semaphore::new(config.max_subscribers)),
            config,
        }
    }

    /// Subscribe to the stream events, unless the configured maximum number of concurrently
    /// served stream clients has been reached; the returned subscription holds the subscriber
    /// slot for its whole lifetime.
    pub fn try_subscribe(&self) -> Option<StreamEventsSubscription> {
        let permit = Arc::clone(&self.subscriber_slots).try_acquire_owned().ok()?;
        Some(StreamEventsSubscription {
            receiver: self.channel.subscribe(),
            _permit: permit,
        })
    }
}

/// A stream event subscription: the broadcast receiver paired with the subscriber slot.
///
/// Note: the slot is held (and the subscriber counted) until the subscription is dropped, i.e.
/// until the client disconnects and axum drops the response stream.
pub struct StreamEventsSubscription {
    pub receiver: tokio::sync::broadcast::Receiver<StreamEvent>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Run the database event pump: forward the stream events committed by the scanner into the
/// broadcast channel of the given handle.
///
/// Note: the pump starts from the most recently committed event, since the events committed
/// before the pump was started are history that is served by the REST endpoints; re-broadcasting
/// them to the currently connected clients would violate the no-replay semantics of the stream.
pub async fn run_database_event_pump(
    mut source: impl StreamEventSource,
    handle: StreamEventsHandle,
) {
    let last_seen_id = source.initial_last_seen_id().await;
    run_event_pump(source, handle.channel, last_seen_id).await;
}

/// Map a node mempool event into a stream event.
///
/// Only successfully processed transactions are of interest; the new tip events and failed
/// transactions are dropped.
fn map_rpc_event_to_tx_seen(event: RpcEvent) -> Option<StreamEvent> {
    match event {
        RpcEvent::NewTip { .. } => None,
        RpcEvent::TransactionProcessed {
            tx_id,
            origin,
            successful,
            ..
        } if successful => {
            let origin = match origin {
                RpcTxOrigin::Local { .. } => TxOrigin::Local,
                RpcTxOrigin::Remote { .. } => TxOrigin::Remote,
            };
            Some(StreamEvent::TxSeen { tx_id, origin })
        }
        RpcEvent::TransactionProcessed { .. } => None,
    }
}

/// Bridge the node's mempool events into the stream event channel.
///
/// The WebSocket subscription is re-established after connection loss; only the successfully
/// processed transactions are forwarded as `TxSeen` events. Note that the events are not
/// hydrated here: a failed hydration must never block the stream, so the stream carries only the
/// transaction ids and the clients are expected to fetch the details through the REST endpoints.
pub async fn run_mempool_bridge(rpc: Arc<NodeRpcClient>, handle: StreamEventsHandle) {
    let mut resubscribe_delay = MEMPOOL_RESUBSCRIBE_DELAY;
    loop {
        // Note: the subscription is bounded by a timeout, so that a stalled WebSocket handshake
        // (e.g. the node accepting the TCP connection but never completing the RPC handshake)
        // cannot wedge the bridge forever without any log output.
        match tokio::time::timeout(
            MEMPOOL_SUBSCRIBE_TIMEOUT,
            MempoolRpcClient::subscribe_to_events(rpc.ws_client()),
        )
        .await
        {
            Ok(Ok(subscription)) => {
                logging::log::info!("Subscribed to node mempool events");
                // Note: the subscription worked, so the next retry does not need to back off.
                resubscribe_delay = MEMPOOL_RESUBSCRIBE_DELAY;
                let mut subscription = subscription;
                while let Some(event) = subscription.next().await {
                    match event {
                        Ok(event) => {
                            if let Some(stream_event) = map_rpc_event_to_tx_seen(event) {
                                // Note: sending fails only when there are no subscribers.
                                let _ = handle.channel.send(stream_event);
                            }
                        }
                        Err(err) => {
                            logging::log::warn!("Node mempool subscription error: {err}");
                            break;
                        }
                    }
                }
                logging::log::warn!("Node mempool subscription closed; re-subscribing");
            }
            Ok(Err(err)) => {
                logging::log::error!("Failed to subscribe to node mempool events: {err}");
            }
            Err(_timed_out) => {
                logging::log::error!(
                    "Timed out subscribing to node mempool events; retrying after a delay"
                );
            }
        }
        // Note: the delay doubles on every failed attempt so that a long node outage cannot
        // flood the logs; it is reset as soon as a subscription succeeds again.
        tokio::time::sleep(resubscribe_delay).await;
        resubscribe_delay = std::cmp::min(resubscribe_delay * 2, MEMPOOL_RESUBSCRIBE_DELAY_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::primitives::{H256, Id};

    fn tx_processed_event(successful: bool, origin: RpcTxOrigin) -> RpcEvent {
        RpcEvent::TransactionProcessed {
            tx_id: Id::new(H256::from_low_u64_be(1)),
            origin,
            relay: mempool::rpc_event::RpcTxRelayPolicy::DoRelay,
            successful,
        }
    }

    #[test]
    fn successful_transaction_maps_to_tx_seen() {
        let origin = RpcTxOrigin::Local {
            origin: mempool::rpc_event::RpcLocalTxOrigin::Mempool,
        };
        let stream_event = map_rpc_event_to_tx_seen(tx_processed_event(true, origin))
            .expect("must map to an event");

        match stream_event {
            StreamEvent::TxSeen { tx_id, origin } => {
                assert_eq!(tx_id, Id::new(H256::from_low_u64_be(1)));
                assert_eq!(origin, TxOrigin::Local);
            }
            _ => panic!("unexpected event type"),
        }
    }

    #[test]
    fn remote_origin_is_preserved() {
        let origin = RpcTxOrigin::Remote {
            peer_id: node_comm::node_traits::PeerId::from_u64(1),
        };
        let stream_event = map_rpc_event_to_tx_seen(tx_processed_event(true, origin))
            .expect("must map to an event");

        match stream_event {
            StreamEvent::TxSeen {
                origin: TxOrigin::Remote,
                ..
            } => {}
            _ => panic!("unexpected event type"),
        }
    }

    #[test]
    fn failed_transactions_and_new_tips_are_dropped() {
        let origin = RpcTxOrigin::Local {
            origin: mempool::rpc_event::RpcLocalTxOrigin::Mempool,
        };
        assert!(map_rpc_event_to_tx_seen(tx_processed_event(false, origin)).is_none());
        assert!(
            map_rpc_event_to_tx_seen(RpcEvent::NewTip {
                id: Id::new(H256::from_low_u64_be(2)),
                height: common::primitives::BlockHeight::new(1),
            })
            .is_none()
        );
    }
}

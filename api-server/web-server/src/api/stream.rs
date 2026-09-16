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

//! The real-time event stream endpoint, exposing the stream events as Server-Sent Events.

use std::{collections::BTreeSet, convert::Infallible, str::FromStr, sync::Arc, time::Duration};

use api_server_common::storage::storage_api::ApiServerStorage;
use api_server_common::streaming::{StreamEvent, StreamEventType, StreamEventTypeParseError};
use axum::{
    extract::{Query, State},
    http::HeaderValue,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures::stream::Stream;
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::{
    ApiServerWebServerState, TxSubmitClient,
    error::{ApiServerWebServerClientError, ApiServerWebServerError},
};

/// The value of the `x-accel-buffering` header that prevents reverse proxies from buffering the
/// event stream.
const X_ACCEL_BUFFERING_VALUE: HeaderValue = HeaderValue::from_static("no");

/// The reconnection hint sent as the first Server-Sent Events frame.
const SSE_RETRY_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    /// The comma-separated subset of the streamed event types, e.g. `types=block,reorg`.
    /// Defaults to all event types.
    types: Option<String>,
}

/// The set of stream event types a client wants to receive.
#[derive(Debug, Clone)]
pub struct StreamEventsFilter(BTreeSet<StreamEventType>);

impl Default for StreamEventsFilter {
    fn default() -> Self {
        Self(StreamEventType::ALL.iter().copied().collect())
    }
}

impl StreamEventsFilter {
    /// Parse a comma-separated list of event type names.
    pub fn parse(types: &str) -> Result<Self, StreamEventTypeParseError> {
        let types = types
            .split(',')
            .map(StreamEventType::from_str)
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self(types))
    }

    fn allows(&self, event: &StreamEvent) -> bool {
        self.0.contains(&event.event_type())
    }
}

pub async fn stream_events<
    T: ApiServerStorage + Send + Sync + 'static,
    R: TxSubmitClient + Send + Sync + 'static,
>(
    State(state): State<ApiServerWebServerState<Arc<T>, Arc<R>>>,
    Query(query): Query<StreamQuery>,
) -> Result<Response, ApiServerWebServerError> {
    let filter = match query.types.as_deref() {
        Some(types) => StreamEventsFilter::parse(types).map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::BadRequest)
        })?,
        None => StreamEventsFilter::default(),
    };

    let receiver = state.stream_events.channel.subscribe();
    let event_stream = sse_event_stream(receiver, filter);

    let sse = Sse::new(event_stream).keep_alive(
        KeepAlive::new()
            .interval(state.stream_events.config.keepalive_interval)
            .text("keepalive"),
    );

    let mut response = sse.into_response();
    response.headers_mut().insert("x-accel-buffering", X_ACCEL_BUFFERING_VALUE);

    Ok(response)
}

fn sse_event_stream(
    receiver: broadcast::Receiver<StreamEvent>,
    filter: StreamEventsFilter,
) -> impl Stream<Item = Result<Event, Infallible>> {
    // Note: the reconnection hint is sent as the first frame so that conforming clients
    // reconnect with the intended interval; the flag below tracks whether it was sent.
    futures::stream::unfold(
        (receiver, filter, false),
        |(mut receiver, filter, retry_sent)| async move {
            if !retry_sent {
                return Some((
                    Ok(Event::default().retry(SSE_RETRY_INTERVAL)),
                    (receiver, filter, true),
                ));
            }

            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        // Note: events the client is not interested in are silently skipped.
                        if filter.allows(&event) {
                            return Some((Ok(sse_event(&event)), (receiver, filter, retry_sent)));
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        // Note: the client fell too far behind; tell it what happened and
                        // continue with the fresh events.
                        return Some((Ok(lag_event(skipped)), (receiver, filter, retry_sent)));
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    )
}

fn sse_event(event: &StreamEvent) -> Event {
    Event::default()
        .event(event.event_name())
        .data(serde_json::to_string(event).unwrap_or_else(|_| {
            // Note: the serialization of these events cannot fail in practice; the fallback
            // keeps the SSE framing intact even if the event payload ever becomes unserializable.
            "{\"error\":\"event serialization failed\"}".to_owned()
        }))
}

fn lag_event(skipped: u64) -> Event {
    Event::default()
        .event("lag")
        .data(serde_json::json!({ "skipped": skipped }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_server_common::streaming::{StreamEvent, TxOrigin};
    use common::{
        chain::block::timestamp::BlockTimestamp,
        primitives::{BlockHeight, H256, Id},
    };

    fn all_kinds_of_events() -> Vec<StreamEvent> {
        vec![
            StreamEvent::TxSeen {
                tx_id: Id::new(H256::from_low_u64_be(1)),
                origin: TxOrigin::Local,
            },
            StreamEvent::Block {
                block_id: Id::new(H256::from_low_u64_be(2)),
                height: BlockHeight::new(1),
                timestamp: BlockTimestamp::from_int_seconds(1000),
                tx_ids: vec![Id::new(H256::from_low_u64_be(1))],
            },
            StreamEvent::Reorg {
                common_ancestor_height: BlockHeight::new(0),
                removed_block_ids: vec![Id::new(H256::from_low_u64_be(3))],
                new_tip_height: BlockHeight::new(1),
            },
        ]
    }

    #[test]
    fn filter_parsing() {
        let filter = StreamEventsFilter::parse("block, reorg").unwrap();
        assert_eq!(
            filter.0,
            [StreamEventType::Block, StreamEventType::Reorg].into()
        );

        assert!(StreamEventsFilter::parse("").is_err());
        assert!(StreamEventsFilter::parse("block,bogus").is_err());

        // Note: defaults to all types.
        assert_eq!(
            StreamEventsFilter::default().0,
            StreamEventType::ALL.iter().copied().collect()
        );
    }

    #[test]
    fn filter_matching() {
        let events = all_kinds_of_events();

        let all = StreamEventsFilter::default();
        assert!(events.iter().all(|event| all.allows(event)));

        let blocks_only = StreamEventsFilter::parse("block").unwrap();
        assert!(!blocks_only.allows(&events[0]));
        assert!(blocks_only.allows(&events[1]));
        assert!(!blocks_only.allows(&events[2]));
    }
}

// Copyright (c) 2024 RBB S.r.l
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

//! Publish-subscribe mechanism for RPC (WebSocket only) using
//! [Ethereum pubsub spec](https://geth.ethereum.org/docs/interacting-with-geth/rpc/pubsub).

use jsonrpsee::{PendingSubscriptionAcceptError, SubscriptionMessage};
use tokio::sync::mpsc;

use utils_networking::broadcaster;

/// Pending subscription. Use [accept] to get subscription sink.
pub type Pending = jsonrpsee::PendingSubscriptionSink;

/// Subscription identifier
pub type SubscriptionId = jsonrpsee::types::SubscriptionId<'static>;

/// Subscription sink. Used to send events to the client.
pub struct Sink<T> {
    sink: jsonrpsee::SubscriptionSink,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Sink<T> {
    fn new(sink: jsonrpsee::SubscriptionSink) -> Self {
        let _phantom = std::marker::PhantomData;
        Self { sink, _phantom }
    }

    async fn accept(pending: Pending) -> Result<Self, Error> {
        Ok(Self::new(pending.accept().await?))
    }
}

impl<T: serde::Serialize> Sink<T> {
    fn message(&self, msg: &T) -> Result<SubscriptionMessage, Error> {
        let method = self.sink.method_name();
        let subscription = self.sink.subscription_id();

        Ok(SubscriptionMessage::new(method, subscription, msg)?)
    }

    /// Send an event to the client
    pub async fn send(&self, msg: &T) -> Result<(), Error> {
        let msg = self.message(msg)?;
        self.sink.send(msg).await.map_err(|_| Error::ConnectionClosed)
    }

    /// Complete when the client closed the subscription or went away.
    ///
    /// Use it to stop a forwarder that would otherwise wait for the next event of a quiet
    /// stream forever; the call is cancel-safe, so it can be awaited in a `select!` with the
    /// next event.
    pub async fn closed(&self) {
        self.sink.closed().await
    }

    /// Get subscription ID.
    pub fn subscription_id(&self) -> SubscriptionId {
        self.sink.subscription_id()
    }

    /// Get subscription method name.
    pub fn method_name(&self) -> &str {
        self.sink.method_name()
    }
}

/// Accept subscription request
pub async fn accept<T>(pending: Pending) -> Result<Sink<T>, Error> {
    Sink::accept(pending).await
}

/// Reject a subscription request with an invalid-parameters error delivered to the client,
/// e.g. when the subscription parameters fail validation.
///
/// Note that returning an error from a subscription method does not reach the client; the
/// request must be rejected explicitly.
pub async fn reject(pending: Pending, message: impl std::fmt::Display) {
    pending
        .reject(jsonrpsee::types::error::ErrorObjectOwned::owned(
            jsonrpsee::types::error::INVALID_PARAMS_CODE,
            message.to_string(),
            None::<Box<serde_json::value::RawValue>>,
        ))
        .await;
}

/// Connect a broadcaster to event sink, transforming and filtering the events on the go
pub async fn connect_broadcast_filter_map<T, U: serde::Serialize>(
    mut event_receiver: broadcaster::Receiver<T>,
    pending: Pending,
    mut filter_map_fn: impl FnMut(T) -> Option<U>,
) -> Reply {
    let subscription = accept::<U>(pending).await?;

    while let Some(event) = event_receiver.recv().await {
        if let Some(event) = filter_map_fn(event) {
            subscription.send(&event).await?;
        }
    }

    Ok(())
}

/// Connect a broadcaster to event sink, transforming and filtering the events on the go
pub async fn connect_broadcast_map<T, U: serde::Serialize>(
    event_receiver: broadcaster::Receiver<T>,
    pending: Pending,
    mut map_fn: impl FnMut(T) -> U,
) -> Reply {
    connect_broadcast_filter_map(event_receiver, pending, |x| Some(map_fn(x))).await
}

/// The error sent to the client when the node ended a subscription because its producer closed
/// the event queue: the subscriber fell behind, or the stream stopped.
pub const CLOSED_BY_NODE: &str =
    "subscription closed by the node: the subscriber fell behind or the stream ended";

/// Connect a bounded queue of events to the subscription sink, transforming and filtering the
/// events on the go. The queue is fed by the producer of the events with `try_send`.
///
/// Closing the queue ends the subscription with the [`CLOSED_BY_NODE`] error, so that the client
/// sees the end of the stream rather than waiting for the next event forever. When the client
/// goes away, the queue is dropped at once (the subscription is watched for closing while
/// waiting for events), so that the producer sees its receiver as closed.
pub async fn connect_mpsc_filter_map<T, U: serde::Serialize>(
    mut event_receiver: mpsc::Receiver<T>,
    pending: Pending,
    mut filter_map_fn: impl FnMut(T) -> Option<U>,
) -> Reply {
    let subscription = accept::<U>(pending).await?;

    loop {
        let event = tokio::select! {
            event = event_receiver.recv() => event,
            // the client is gone: nothing left to forward
            () = subscription.closed() => return Ok(()),
        };
        let Some(event) = event else {
            // the producer closed the queue: tell the client that the subscription is over
            return Err(CLOSED_BY_NODE.into());
        };
        if let Some(event) = filter_map_fn(event) {
            subscription.send(&event).await?;
        }
    }
}

/// Connect a broadcaster to event sink
pub async fn connect_broadcast<T: serde::Serialize>(
    event_receiver: broadcaster::Receiver<T>,
    pending: Pending,
) -> Reply {
    connect_broadcast_filter_map(event_receiver, pending, Some).await
}

/// Subscription processing error
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("RPC connection closed")]
    ConnectionClosed,

    #[error("Failed to encode RPC message: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Cannot accept RPC subscription: {0}")]
    Accept(#[from] PendingSubscriptionAcceptError),
}

/// Subscription method reply type
pub type Reply = Result<(), jsonrpsee::core::SubscriptionError>;

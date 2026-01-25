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

//! Definitions facilitating subsystem calls

pub mod blocking;
mod handle;

pub use handle::{Handle, SubmitOnlyHandle};

use std::{
    future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Instant,
};

use utils::sync::Arc;

use crate::error::{CallError, ResponseError, SubmissionError};

use futures::future::BoxFuture;
use tokio::sync::{mpsc, oneshot};

// Internal action types sent in the channel.
type ActionRefFn<T> = Box<dyn Send + FnOnce(&T) -> BoxFuture<()>>;
type ActionMutFn<T> = Box<dyn Send + FnOnce(&mut T) -> BoxFuture<()>>;

pub struct ActionRef<T: ?Sized> {
    pub(crate) submitted_at: Instant,
    pub(crate) label: Option<&'static str>,
    pub(crate) func: ActionRefFn<T>,
}

pub struct ActionMut<T: ?Sized> {
    pub(crate) submitted_at: Instant,
    pub(crate) label: Option<&'static str>,
    pub(crate) func: ActionMutFn<T>,
}

pub enum Action<T: ?Sized> {
    Ref(ActionRef<T>),
    Mut(ActionMut<T>),
}

impl<T: ?Sized> Action<T> {
    pub fn new_ref(func: ActionRefFn<T>, label: Option<&'static str>) -> Self {
        Self::Ref(ActionRef {
            submitted_at: Instant::now(),
            label,
            func,
        })
    }

    pub fn new_mut(func: ActionMutFn<T>, label: Option<&'static str>) -> Self {
        Self::Mut(ActionMut {
            submitted_at: Instant::now(),
            label,
            func,
        })
    }
}

pub type ActionSender<T> = mpsc::UnboundedSender<Action<T>>;

#[derive(Debug)]
pub struct QueueWatch {
    start: Instant,
    last_submit_ms: AtomicU64,
    last_dequeue_ms: AtomicU64,
    queue_depth: AtomicU64,
}

impl QueueWatch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            last_submit_ms: AtomicU64::new(0),
            last_dequeue_ms: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
        })
    }

    pub fn mark_submit(&self) {
        let now_ms = self.start.elapsed().as_millis() as u64;
        self.last_submit_ms.store(now_ms, Ordering::Relaxed);
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_submit_failed(&self) {
        let _ = self.queue_depth.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |val| val.checked_sub(1),
        );
    }

    pub fn mark_dequeue(&self) {
        let now_ms = self.start.elapsed().as_millis() as u64;
        self.last_dequeue_ms.store(now_ms, Ordering::Relaxed);
        let _ = self.queue_depth.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |val| val.checked_sub(1),
        );
    }

    pub fn queue_depth(&self) -> u64 {
        self.queue_depth.load(Ordering::Relaxed)
    }

    pub fn last_submit_ms(&self) -> u64 {
        self.last_submit_ms.load(Ordering::Relaxed)
    }

    pub fn last_dequeue_ms(&self) -> u64 {
        self.last_dequeue_ms.load(Ordering::Relaxed)
    }
}

/// Call response that can be polled for result
#[must_use = "Subsystem call response ignored"]
pub struct CallResponse<T>(oneshot::Receiver<T>);

impl<T> CallResponse<T> {
    fn new(receiver: oneshot::Receiver<T>) -> Self {
        Self(receiver)
    }

    fn blocking_recv(self) -> Result<T, ResponseError> {
        self.0.blocking_recv().map_err(|_| ResponseError::NoResponse)
    }
}

impl<T> future::Future for CallResponse<T> {
    type Output = Result<T, ResponseError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        std::pin::pin!(&mut self.0).poll(cx).map_err(|_| ResponseError::NoResponse)
    }
}

/// Result of a remote subsystem call.
///
/// Calls happen asynchronously. A value of this type represents the return value of the call of
/// type `T`. To actually fetch the return value, use `.await`. Alternatively, use
/// [CallResult::response] to verify if the call submission succeeded and get the return value at
/// a later time.
#[must_use = "Subsystem call result ignored"]
pub struct CallResult<T>(Result<CallResponse<T>, SubmissionError>);

impl<T> CallResult<T> {
    fn new(result: Result<CallResponse<T>, SubmissionError>) -> Self {
        Self(result)
    }

    /// Get the corresponding [`CallResponse`], with the opportunity to handle errors at send time.
    pub fn response(self) -> Result<CallResponse<T>, SubmissionError> {
        self.0
    }

    /// Get the result, wait for it by blocking the thread. Panics if called from async context.
    fn blocking_get(self) -> Result<T, CallError> {
        Ok(self.0?.blocking_recv()?)
    }
}

impl<T> future::Future for CallResult<T> {
    type Output = Result<T, CallError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let future = async { Ok(self.0.as_mut().map_err(|e| *e)?.await?) };
        std::pin::pin!(future).poll(cx)
    }
}

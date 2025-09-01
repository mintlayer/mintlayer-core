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

//! Subsystem handle definitions (non-blocking versions)

use futures::future::BoxFuture;

use logging::log;
use tracing::Instrument as _;
use utils::shallow_clone::ShallowClone;

use crate::{
    calls::{Action, ActionSender, CallResponse, CallResult},
    error::SubmissionError,
};

/// Submit-only subsystem handle. Can be used when a call result is not needed.
pub struct SubmitOnlyHandle<T: ?Sized> {
    // Send the subsystem stuff to do.
    action_tx: ActionSender<T>,
}

impl<T: ?Sized> Clone for SubmitOnlyHandle<T> {
    fn clone(&self) -> Self {
        self.shallow_clone()
    }
}

impl<T: ?Sized> ShallowClone for SubmitOnlyHandle<T> {
    fn shallow_clone(&self) -> Self {
        let action_tx = self.action_tx.clone();
        Self { action_tx }
    }
}

impl<T: ?Sized + Send + Sync + 'static> SubmitOnlyHandle<T> {
    pub(crate) fn new(action_tx: ActionSender<T>) -> Self {
        Self { action_tx }
    }

    fn send_action(&self, action: Action<T>) -> Result<(), SubmissionError> {
        self.action_tx.send(action).map_err(|_| SubmissionError::ChannelClosed)
    }

    /// Submit an async procedure to be performed by the subsystem (mutable).
    pub fn submit_async_mut(
        &self,
        func: impl FnOnce(&mut T) -> BoxFuture<()> + Send + 'static,
    ) -> Result<(), SubmissionError> {
        self.send_action(Action::Mut(Box::new(func)))
    }

    /// Submit an async procedure to be performed by the subsystem.
    pub fn submit_async(
        &self,
        func: impl FnOnce(&T) -> BoxFuture<()> + Send + 'static,
    ) -> Result<(), SubmissionError> {
        self.send_action(Action::Ref(Box::new(func)))
    }

    /// Submit a procedure to be preformed by the subsystem (mutable).
    pub fn submit_mut(
        &self,
        func: impl FnOnce(&mut T) + Send + 'static,
    ) -> Result<(), SubmissionError> {
        self.send_action(Action::Mut(Box::new(move |subsys| {
            Box::pin(async { func(subsys) })
        })))
    }

    /// Submit a procedure to be preformed by the subsystem.
    pub fn submit(&self, func: impl FnOnce(&T) + Send + 'static) -> Result<(), SubmissionError> {
        self.send_action(Action::Ref(Box::new(move |subsys| {
            Box::pin(async { func(subsys) })
        })))
    }
}

/// Subsystem handle.
///
/// This allows the user to interact with the subsystem from the outside. Currently, it only
/// supports calling functions on the subsystem.
pub struct Handle<T: ?Sized>(SubmitOnlyHandle<T>);

impl<T: ?Sized> Clone for Handle<T> {
    fn clone(&self) -> Self {
        self.shallow_clone()
    }
}

impl<T: ?Sized> ShallowClone for Handle<T> {
    fn shallow_clone(&self) -> Self {
        Self(self.0.shallow_clone())
    }
}

impl<T: ?Sized + Send + Sync + 'static> Handle<T> {
    /// Create a new subsystem handle.
    pub(crate) fn new(submit_only_handle: SubmitOnlyHandle<T>) -> Self {
        Self(submit_only_handle)
    }

    /// Get an equivalent [SubmitOnlyHandle].
    pub fn as_submit_only(&self) -> &SubmitOnlyHandle<T> {
        &self.0
    }

    /// Call an async procedure to the subsystem. Result has to be await-ed explicitly
    pub fn call_async_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> BoxFuture<R> + Send + 'static,
    ) -> CallResult<R> {
        // Note: need to retrieve the tracing span in advance and then call `instrument` with it
        // (as opposed to calling `in_current_span` on the future directly - this won't work because
        // the current span will be different at the point of the call).
        let current_tracing_span = tracing::Span::current();
        let (rtx, rrx) = tokio::sync::oneshot::channel::<R>();
        let result = self.0.submit_async_mut(move |subsys| {
            Box::pin(async move {
                if rtx.send(func(subsys).instrument(current_tracing_span).await).is_err() {
                    log::trace!("Subsystem call (mut) result ignored");
                }
            })
        });
        CallResult::new(result.map(|()| CallResponse::new(rrx)))
    }

    /// Call an async procedure to the subsystem (immutable).
    pub fn call_async<R: Send + 'static>(
        &self,
        func: impl FnOnce(&T) -> BoxFuture<R> + Send + 'static,
    ) -> CallResult<R> {
        // Same note about the tracing span as in `call_async_mut` above.
        let current_tracing_span = tracing::Span::current();
        let (rtx, rrx) = tokio::sync::oneshot::channel::<R>();
        let result = self.0.submit_async(move |subsys| {
            Box::pin(async move {
                if rtx.send(func(subsys).instrument(current_tracing_span).await).is_err() {
                    log::trace!("Subsystem call result ignored");
                }
            })
        });
        CallResult::new(result.map(|()| CallResponse::new(rrx)))
    }

    /// Call a procedure to the subsystem.
    pub fn call_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> R + Send + 'static,
    ) -> CallResult<R> {
        // Note: originally we were creating the future via `core::future::ready` instead of using
        // an `async` block. But `instrument`-ing the `Ready` future (which happens inside
        // `call_async_mut`) doesn't work for some reason.
        self.call_async_mut(|this| Box::pin(async { func(this) }))
    }

    /// Call a procedure to the subsystem (immutable).
    pub fn call<R: Send + 'static>(
        &self,
        func: impl FnOnce(&T) -> R + Send + 'static,
    ) -> CallResult<R> {
        // Same note about the async block as in `call_mut` above.
        self.call_async(|this| Box::pin(async { func(this) }))
    }
}

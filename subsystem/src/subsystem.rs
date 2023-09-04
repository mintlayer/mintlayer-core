// Copyright (c) 2022-2023 RBB S.r.l
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

use std::{pin::Pin, task::Poll};

use futures::future::BoxFuture;
use tokio::sync::{mpsc, oneshot};

use logging::log;
use utils::shallow_clone::ShallowClone;

/// Defines hooks into a subsystem lifecycle.
#[async_trait::async_trait]
pub trait Subsystem: 'static + Send + Sync + Sized {
    /// Custom shutdown procedure.
    async fn shutdown(self) {}
}

/// Subsystem configuration
pub struct SubsystemConfig {
    /// Subsystem name
    pub subsystem_name: &'static str,
}

impl SubsystemConfig {
    /// New configuration with given name, all other options are defaults.
    pub(crate) fn named(subsystem_name: &'static str) -> Self {
        Self { subsystem_name }
    }
}

// Internal action types sent in the channel.
type ActionRefFn<T> = Box<dyn Send + FnOnce(&T) -> BoxFuture<()>>;
type ActionMutFn<T> = Box<dyn Send + FnOnce(&mut T) -> BoxFuture<()>>;

pub enum Action<T: ?Sized> {
    Ref(ActionRefFn<T>),
    Mut(ActionMutFn<T>),
}

impl<T: ?Sized> Action<T> {
    /// Handle a call without any fancy processing, just using a plain mut reference
    pub fn handle_call_mut(self, obj: &mut T) -> BoxFuture<()> {
        match self {
            Self::Ref(action) => action(&*obj),
            Self::Mut(action) => action(obj),
        }
    }
}

/// Call request
pub struct CallRequest<T: ?Sized>(pub(crate) mpsc::UnboundedReceiver<Action<T>>);

impl<T: 'static + ?Sized> CallRequest<T> {
    /// Receive an external call to this subsystem.
    pub async fn recv(&mut self) -> Action<T> {
        match self.0.recv().await {
            // We have a call, return it
            Some(action) => action,
            // All handles to this subsystem dropped, suspend call handling.
            None => std::future::pending().await,
        }
    }
}

/// Call response that can be polled for result
pub struct CallResponse<T>(oneshot::Receiver<T>);

impl<T> CallResponse<T> {
    fn blocking_recv(self) -> Result<T, CallError> {
        self.0.blocking_recv().map_err(|_| CallError::ResultFetchFailed)
    }
}

impl<T> std::future::Future for CallResponse<T> {
    type Output = Result<T, CallError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        // TODO(PR) better error
        std::pin::pin!(&mut self.0).poll(cx).map_err(|_| CallError::ResultFetchFailed)
    }
}

/// Shutdown request
pub struct ShutdownRequest(pub(crate) oneshot::Receiver<()>);

impl ShutdownRequest {
    /// Receive a shutdown request.
    pub async fn recv(&mut self) {
        if (&mut self.0).await.is_err() {
            log::error!("Shutdown channel sender closed prematurely")
        }
    }
}

pub type ActionSender<T> = mpsc::UnboundedSender<Action<T>>;

/// Subsystem handle.
///
/// This allows the user to interact with the subsystem from the outside. Currently, it only
/// supports calling functions on the subsystem.
pub struct Handle<T: ?Sized> {
    // Send the subsystem stuff to do.
    action_tx: ActionSender<T>,
}

impl<T: ?Sized> Clone for Handle<T> {
    fn clone(&self) -> Self {
        self.shallow_clone()
    }
}

impl<T: ?Sized> ShallowClone for Handle<T> {
    fn shallow_clone(&self) -> Self {
        Self {
            action_tx: self.action_tx.clone(),
        }
    }
}

#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum CallError {
    #[error("Call submission failed")]
    SubmissionFailed,
    #[error("Result retrieval failed")]
    ResultFetchFailed,
}

/// Result of a remote subsystem call.
///
/// Calls happen asynchronously. A value of this type represents the return value of the call of
/// type `T`. To actually fetch the return value, use `.await`. Alternatively, use
/// [CallResult::response] to verify if the call submission succeeded and get the return value at
/// a later time.
pub struct CallResult<T>(Result<CallResponse<T>, CallError>);

impl<T> CallResult<T> {
    /// Get the corresponding [`CallResponse`], with the opportunity to handle errors at send time.
    pub fn response(self) -> Result<CallResponse<T>, CallError> {
        self.0
    }

    /// Get the result, wait for it by blocking the thread.
    ///
    /// Panics if called from async context
    pub(crate) fn blocking_get(self) -> Result<T, CallError> {
        self.0.and_then(|resp| resp.blocking_recv())
    }
}

impl<T> std::future::Future for CallResult<T> {
    type Output = Result<T, CallError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.0
            .as_mut()
            .map_or_else(|err| Poll::Ready(Err(*err)), |res| Pin::new(res).poll(cx))
    }
}

impl<T: ?Sized + Send + Sync + 'static> Handle<T> {
    /// Crate a new subsystem handle.
    pub(crate) fn new(action_tx: ActionSender<T>) -> Self {
        Self { action_tx }
    }

    pub fn send_action<R: Send + 'static>(
        &self,
        action: impl FnOnce(oneshot::Sender<R>) -> Action<T>,
    ) -> CallResult<R> {
        let (rtx, rrx) = oneshot::channel::<R>();

        // TODO(PR): Better error
        let result = self
            .action_tx
            .send(action(rtx))
            .map(|()| CallResponse(rrx))
            .map_err(|_e| CallError::SubmissionFailed);

        CallResult(result)
    }

    /// Call an async procedure to the subsystem. Result has to be await-ed explicitly
    pub fn call_async_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> BoxFuture<R> + Send + 'static,
    ) -> CallResult<R> {
        self.send_action(|rtx| {
            Action::Mut(Box::new(move |subsys| {
                Box::pin(async move {
                    if rtx.send(func(subsys).await).is_err() {
                        log::trace!("Subsystem call (mut) result ignored");
                    }
                })
            }))
        })
    }

    /// Call an async procedure to the subsystem (immutable).
    pub fn call_async<R: Send + 'static>(
        &self,
        func: impl FnOnce(&T) -> BoxFuture<R> + Send + 'static,
    ) -> CallResult<R> {
        self.send_action(|rtx| {
            Action::Ref(Box::new(move |subsys| {
                Box::pin(async move {
                    if rtx.send(func(subsys).await).is_err() {
                        log::trace!("Subsystem call (ref) result ignored");
                    }
                })
            }))
        })
    }

    /// Call a procedure to the subsystem.
    pub fn call_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> R + Send + 'static,
    ) -> CallResult<R> {
        self.call_async_mut(|this| Box::pin(async { func(this) }))
    }

    /// Call a procedure to the subsystem (immutable).
    pub fn call<R: Send + 'static>(
        &self,
        func: impl FnOnce(&T) -> R + Send + 'static,
    ) -> CallResult<R> {
        self.call_async(|this| Box::pin(core::future::ready(func(this))))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn named_config() {
        let config = SubsystemConfig::named("foo");
        assert_eq!(config.subsystem_name, "foo");
    }
}

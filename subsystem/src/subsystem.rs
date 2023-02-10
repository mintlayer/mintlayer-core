// Copyright (c) 2022 RBB S.r.l
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

use std::{pin::Pin, task};

use futures::future::BoxFuture;
use logging::log;
use tokio::sync::{broadcast, mpsc, oneshot};

/// Defines hooks into a subsystem lifecycle.
#[async_trait::async_trait]
pub trait Subsystem: 'static + Send + Sized {
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

// Internal action type sent in the channel.
type Action<T, R> = Box<dyn Send + FnOnce(&mut T) -> BoxFuture<R>>;

/// Call request
pub struct CallRequest<T: ?Sized>(pub(crate) mpsc::UnboundedReceiver<Action<T, ()>>);

impl<T: 'static + ?Sized> CallRequest<T> {
    /// Receive an external call to this subsystem.
    pub async fn recv(&mut self) -> Action<T, ()> {
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

impl<T> std::future::Future for CallResponse<T> {
    type Output = Result<T, CallError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|_| CallError::ResultFetchFailed)
    }
}

/// Shutdown request
pub struct ShutdownRequest(pub(crate) broadcast::Receiver<()>);

impl ShutdownRequest {
    /// Receive a shutdown request.
    pub async fn recv(&mut self) {
        match self.0.recv().await {
            Err(broadcast::error::RecvError::Lagged(_)) => {
                panic!("Multiple shutdown broadcast requests issued")
            }
            Err(broadcast::error::RecvError::Closed) => {
                panic!("Shutdown channel sender closed prematurely")
            }
            Ok(()) => (),
        }
    }
}

pub type ActionSender<T> = mpsc::UnboundedSender<Action<T, ()>>;

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
/// [CallResult::response] to verify if the call submission suceeded and get the return value at
/// a later time.
pub struct CallResult<T>(Result<CallResponse<T>, CallError>);

impl<T> CallResult<T> {
    /// Get the corresponding [`CallResponse`], with the opportunity to handle errors at send time.
    pub fn response(self) -> Result<CallResponse<T>, CallError> {
        self.0
    }
}

impl<T> std::future::Future for CallResult<T> {
    type Output = Result<T, CallError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        self.0.as_mut().map_or_else(
            |err| task::Poll::Ready(Err(*err)),
            |res| Pin::new(res).poll(cx),
        )
    }
}

impl<T: ?Sized + Send + 'static> Handle<T> {
    /// Crate a new subsystem handle.
    pub(crate) fn new(action_tx: ActionSender<T>) -> Self {
        Self { action_tx }
    }

    /// Call an async procedure to the subsystem. Result has to be await-ed explicitly
    pub fn call_async_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> BoxFuture<R> + Send + 'static,
    ) -> CallResult<R> {
        let (rtx, rrx) = oneshot::channel::<R>();

        let res = self
            .action_tx
            .send(Box::new(move |subsys| {
                Box::pin(async move {
                    if rtx.send(func(subsys).await).is_err() {
                        log::trace!("Subsystem call result ignored");
                    }
                })
            }))
            .map(|()| CallResponse(rrx))
            .map_err(|_e| CallError::SubmissionFailed);

        CallResult(res)
    }

    /// Call an async procedure to the subsystem (immutable).
    pub fn call_async<R: Send + 'static>(
        &self,
        func: impl FnOnce(&T) -> BoxFuture<R> + Send + 'static,
    ) -> CallResult<R> {
        self.call_async_mut(|this| func(this))
    }

    /// Call a procedure to the subsystem.
    pub fn call_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> R + Send + 'static,
    ) -> CallResult<R> {
        self.call_async_mut(|this| Box::pin(core::future::ready(func(this))))
    }

    /// Call a procedure to the subsystem (immutable).
    pub fn call<R: Send + 'static>(
        &self,
        func: impl FnOnce(&T) -> R + Send + 'static,
    ) -> CallResult<R> {
        self.call_mut(|this| func(this))
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

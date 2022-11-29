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
type Action<T, R> = Box<dyn Send + for<'a> FnOnce(&'a mut T) -> BoxFuture<'a, R>>;

/// Call request
pub struct CallRequest<T>(pub(crate) mpsc::UnboundedReceiver<Action<T, ()>>);

impl<T: 'static> CallRequest<T> {
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
        Pin::new(&mut self.0).poll(cx).map(|r| r.map_err(|_| CallError::SubsystemDead))
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
///
/// There are two sets of methods for communication with and control of subsystem:
/// * Methods starting with `submit_` will submit the closure given as the argument for processing
///   by the subsystem. The result is not immediately ready and the current task is free to
///   continue its operation and `.await` the return value at a latet point (or decide not to).
/// * Methods starting with `call_` will also submit the closure and suspend the current task until
///   the result is ready, returning it directly.
pub struct Handle<T> {
    // Send the subsystem stuff to do.
    action_tx: ActionSender<T>,
}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self {
            action_tx: self.action_tx.clone(),
        }
    }
}

#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum CallError {
    #[error("Callee subsystem has terminated")]
    SubsystemDead,
}

impl<T: Send + 'static> Handle<T> {
    /// Crate a new subsystem handle.
    pub(crate) fn new(action_tx: ActionSender<T>) -> Self {
        Self { action_tx }
    }

    /// Submit an async procedure to the subsystem. Result has to be await-ed explicitly
    pub fn submit_async_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> BoxFuture<'a, R> + Send + 'static,
    ) -> Result<CallResponse<R>, CallError> {
        let (rtx, rrx) = oneshot::channel::<R>();
        let rrx = CallResponse(rrx);

        self.action_tx
            .send(Box::new(move |subsys| {
                Box::pin(async move {
                    if rtx.send(func(subsys).await).is_err() {
                        log::trace!("Subsystem call result ignored");
                    }
                })
            }))
            .map_err(|_| CallError::SubsystemDead)?;

        Ok(rrx)
    }

    /// Submit an async procedure to the subsystem (immutable).
    pub fn submit_async<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> BoxFuture<'a, R> + Send + 'static,
    ) -> Result<CallResponse<R>, CallError> {
        self.submit_async_mut(|this| func(this))
    }

    /// Subimt a procedure to the subsystem.
    pub fn submit_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> R + Send + 'static,
    ) -> Result<CallResponse<R>, CallError> {
        self.submit_async_mut(|this| Box::pin(core::future::ready(func(this))))
    }

    /// Submit a procedure to the subsystem (immutable).
    pub fn submit<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> R + Send + 'static,
    ) -> Result<CallResponse<R>, CallError> {
        self.submit_mut(|this| func(this))
    }

    /// Dispatch an async function call to the subsystem.
    pub async fn call_async_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> BoxFuture<'a, R> + Send + 'static,
    ) -> Result<R, CallError> {
        self.submit_async_mut(func)?.await
    }

    /// Dispatch an async function call to the subsystem (immutable).
    pub async fn call_async<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> BoxFuture<'a, R> + Send + 'static,
    ) -> Result<R, CallError> {
        self.submit_async(func)?.await
    }

    /// Dispatch a function call to the subsystem.
    pub async fn call_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> R + Send + 'static,
    ) -> Result<R, CallError> {
        self.submit_mut(func)?.await
    }

    /// Dispatch a function call to the subsystem (immutable).
    pub async fn call<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> R + Send + 'static,
    ) -> Result<R, CallError> {
        self.submit(func)?.await
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

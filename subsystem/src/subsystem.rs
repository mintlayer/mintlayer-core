// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): L. Kuklinek

use futures::future::BoxFuture;
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
    /// Capacity of the call request channel
    pub call_queue_capacity: usize,
}

impl SubsystemConfig {
    const DEFAULT_CALL_QUEUE_CAPACITY: usize = 64;
    const DEFAULT_SUBSYSTEM_NAME: &'static str = "<unnamed>";

    /// New configuration with given name, all other options are defaults.
    pub(crate) fn named(subsystem_name: &'static str) -> Self {
        Self {
            subsystem_name,
            call_queue_capacity: Self::DEFAULT_CALL_QUEUE_CAPACITY,
        }
    }
}

impl Default for SubsystemConfig {
    fn default() -> Self {
        Self {
            subsystem_name: Self::DEFAULT_SUBSYSTEM_NAME,
            call_queue_capacity: Self::DEFAULT_CALL_QUEUE_CAPACITY,
        }
    }
}

// Internal action type sent in the channel.
type Action<T, R> = Box<dyn Send + for<'a> FnOnce(&'a mut T) -> BoxFuture<'a, R>>;

/// Call request
pub struct CallRequest<T>(pub(crate) mpsc::Receiver<Action<T, ()>>);

impl<T: 'static + Send> CallRequest<T> {
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

/// Subsystem handle.
///
/// This allows the user to interact with the subsystem from the outside. Currently, it only
/// supports calling functions on the subsystem.
pub struct Handle<T> {
    // Send the subsystem stuff to do.
    action_tx: mpsc::Sender<Action<T, ()>>,
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
    #[error("Callee subsysytem has terminated")]
    SubsystemDead,
}

impl<T: Send + 'static> Handle<T> {
    /// Crate a new subsystem handle.
    pub(crate) fn new(action_tx: mpsc::Sender<Action<T, ()>>) -> Self {
        Self { action_tx }
    }

    /// Dispatch an async function call to the subsystem
    pub async fn call_async_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> BoxFuture<'a, R> + Send + 'static,
    ) -> Result<R, CallError> {
        let (rtx, rrx) = oneshot::channel::<R>();

        self.action_tx
            .send(Box::new(move |subsys| {
                Box::pin(async move {
                    let result = func(subsys).await;
                    rtx.send(result).ok().expect("Value return channel closed");
                })
            }))
            .await
            .map_err(|_| CallError::SubsystemDead)?;

        rrx.await.map_err(|_| CallError::SubsystemDead)
    }

    /// Dispatch an async function call to the subsystem (immutable)
    pub async fn call_async<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> BoxFuture<'a, R> + Send + 'static,
    ) -> Result<R, CallError> {
        self.call_async_mut(|this| func(this)).await
    }

    /// Dispatch a function call to the subsystem
    pub async fn call_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> R + Send + 'static,
    ) -> Result<R, CallError> {
        self.call_async_mut(|this| Box::pin(core::future::ready(func(this)))).await
    }

    /// Dispatch a function call to the subsystem (immutable)
    pub async fn call<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> R + Send + 'static,
    ) -> Result<R, CallError> {
        self.call_mut(|this| func(this)).await
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_queue_size_with_named_config() {
        let config = SubsystemConfig::named("foo");
        assert_eq!(config.subsystem_name, "foo");
        assert_eq!(
            config.call_queue_capacity,
            SubsystemConfig::DEFAULT_CALL_QUEUE_CAPACITY
        );
    }
}

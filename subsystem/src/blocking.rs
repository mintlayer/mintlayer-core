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

//! Blocking interface to subsystem.

use crate::{subsystem::CallError, CallResult, Handle};
use futures::future::BoxFuture;

/// Blocking version of [subsystem::Handle].
///
/// This should be used sparingly as blocking calls induce non-trivial overhead. The call takes up
/// a thread in the runtime thread pool. If there is not enough threads for all simultaneous
/// blocking calls, a new one is spawned.
pub struct BlockingHandle<T: ?Sized>(Handle<T>);

impl<T: 'static + Send + ?Sized> BlockingHandle<T> {
    /// A new blocking handle with a dedicated worker
    pub fn new(handle: Handle<T>) -> Self {
        Self(handle)
    }

    /// Get the inner handle
    pub fn handle(&self) -> &Handle<T> {
        &self.0
    }

    /// Perform given closure in a worker, passing the handle to it, get the result
    fn with_handle<R: 'static + Send>(
        &self,
        func: impl 'static + Send + FnOnce(&Handle<T>) -> CallResult<R>,
    ) -> Result<R, CallError> {
        // Get the future associated with the function call result
        let result = func(self.handle());

        // Deal with it according to the current runtime context
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                assert_eq!(
                    rt.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread,
                    "Only multi-threaded Tokio runtime supported by blocking subsystem handle"
                );
                tokio::task::block_in_place(|| result.blocking_get())
            }
            Err(err) => {
                if err.is_missing_context() {
                    result.blocking_get()
                } else {
                    panic!("Unexpected error while getting tokio runtime")
                }
            }
        }
    }

    /// Blocking variant of [Handle::call_async_mut]
    pub fn call_async_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> BoxFuture<R> + Send + 'static,
    ) -> Result<R, CallError> {
        self.with_handle(|h| h.call_async_mut(func))
    }

    /// Blocking variant of [Handle::call_async]
    pub fn call_async<R: Send + 'static>(
        &self,
        func: impl FnOnce(&T) -> BoxFuture<R> + Send + 'static,
    ) -> Result<R, CallError> {
        self.with_handle(|h| h.call_async(func))
    }

    /// Blocking variant of [Handle::call_mut]
    pub fn call_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut T) -> R + Send + 'static,
    ) -> Result<R, CallError> {
        self.with_handle(|h| h.call_mut(func))
    }

    /// Blocking variant of [Handle::call]
    pub fn call<R: 'static + Send>(
        &self,
        func: impl 'static + Send + FnOnce(&T) -> R,
    ) -> Result<R, CallError> {
        self.with_handle(|h| h.call(func))
    }
}

impl<T: 'static + Send + ?Sized> From<Handle<T>> for BlockingHandle<T> {
    fn from(handle: Handle<T>) -> Self {
        Self::new(handle)
    }
}

#[cfg(test)]
mod assertions {
    use super::BlockingHandle;
    static_assertions::assert_impl_all!(BlockingHandle<()>: Send, Sync);
}

// Copyright (c) 2021-2026 RBB S.r.l
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

//! Wrappers for tokio task-launching functions that also accept a "task name", which will be
//! visible in tokio-console when it's attached to the app (requires the corresponding
//! compile-time feature).

use std::future::Future;

use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tracing::{Instrument, Span};

// Note:
// - "track_caller" is needed for tokio-console to be able to correctly display the location,
//   otherwise it'll always be "utils/src/tokio_utils.rs".
// - It'd be better if enabling tokio-console was done via a command-line option, without the
//   need to rebuild the app. But this would require to always use the currently unstable builder
//   APIs, which means that we'd have to return proper Results from the "tokio_spawn_" functions
//   and make sure the caller code can handle potential errors (because even though most functions
//   can't return an error now, they may start doing so in future versions of Tokio, given that
//   the API is considered unstable), which is not always easy to do.

#[track_caller]
pub fn tokio_spawn_in_current_tracing_span<Fut>(
    future: Fut,
    task_name: &str,
) -> JoinHandle<Fut::Output>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    tokio_spawn(future.in_current_span(), task_name)
}

#[track_caller]
pub fn tokio_spawn_in_tracing_span<Fut>(
    future: Fut,
    span: Span,
    task_name: &str,
) -> JoinHandle<Fut::Output>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    tokio_spawn(future.instrument(span), task_name)
}

#[track_caller]
#[allow(unused_variables)]
pub fn tokio_spawn<Fut>(future: Fut, task_name: &str) -> JoinHandle<Fut::Output>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[cfg(feature = "tokio-console")]
    return tokio::task::Builder::new()
        .name(task_name)
        .spawn(future)
        // Note: as of tokio 1.49, this cannot fail
        .expect("task::Builder::spawn failed");

    #[cfg(not(feature = "tokio-console"))]
    return tokio::spawn(future);
}

#[track_caller]
#[allow(unused_variables)]
pub fn tokio_spawn_blocking<Func, Output>(func: Func, task_name: &str) -> JoinHandle<Output>
where
    Func: FnOnce() -> Output + Send + 'static,
    Output: Send + 'static,
{
    // Note: this actually behaves slightly differently compared to the normal `task::spawn_blocking`:
    // the latter returns a bogus handle when the internal `SpawnError::ShuttingDown` occurs
    // (see https://github.com/tokio-rs/tokio/blob/tokio-1.49.0/tokio/src/runtime/blocking/pool.rs#L320-L327),
    // while the builder method will return an actual error in this case.
    // Since the "tokio-console" feature is for debugging purposes only, it's ok to panic when
    // the task is being spawned during shutdown.
    #[cfg(feature = "tokio-console")]
    return tokio::task::Builder::new()
        .name(task_name)
        .spawn_blocking(func)
        .expect("task::Builder::spawn_blocking failed");

    #[cfg(not(feature = "tokio-console"))]
    return tokio::task::spawn_blocking(func);
}

#[track_caller]
#[allow(unused_variables)]
pub fn tokio_spawn_in_join_set<Fut>(
    set: &mut JoinSet<Fut::Output>,
    future: Fut,
    task_name: &str,
) -> AbortHandle
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[cfg(feature = "tokio-console")]
    return set
        .build_task()
        .name(task_name)
        .spawn(future)
        // Note: as of tokio 1.49, this cannot fail
        .expect("join_set::Builder::spawn failed");

    #[cfg(not(feature = "tokio-console"))]
    return set.spawn(future);
}

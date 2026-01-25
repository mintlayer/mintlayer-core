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

//! Implementation of tasks that constitute the subsystem mechanism.

use tokio::{
    sync::{mpsc, oneshot, RwLock},
    task::JoinSet,
};
use tracing::Instrument;

use logging::log;
use utils::{once_destructor::OnceDestructor, sync::Arc};

use crate::{calls::Action, SubmitOnlyHandle, Subsystem};

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

const CHAINSTATE_WATCHDOG_NO_PROGRESS_AFTER: Duration = Duration::from_secs(10);
const CHAINSTATE_WATCHDOG_POLL_INTERVAL: Duration = Duration::from_secs(1);
const CHAINSTATE_WATCHDOG_WRITE_LOCK_WARN_AFTER: Duration = Duration::from_secs(10);
const CHAINSTATE_WATCHDOG_QUEUE_WARN_AFTER: Duration = Duration::from_secs(10);
const CHAINSTATE_WRITE_KIND_NONE: u8 = 0;
const CHAINSTATE_WRITE_KIND_ACTION_MUT: u8 = 1;
const CHAINSTATE_WRITE_KIND_BACKGROUND: u8 = 2;

fn chainstate_write_kind_name(kind: u8) -> &'static str {
    match kind {
        CHAINSTATE_WRITE_KIND_ACTION_MUT => "action_mut",
        CHAINSTATE_WRITE_KIND_BACKGROUND => "background_work",
        _ => "none",
    }
}

/// Handle a task completion result
pub fn handle_result(full_name: &str, task_type: &str, res: Result<(), tokio::task::JoinError>) {
    log::trace!("Subsystem {full_name} {task_type} task finished");
    if let Err(err) = res {
        log::error!("Subsystem {full_name}: failed to join {task_type} task: {err}");
        if let Ok(p) = err.try_into_panic() {
            std::panic::resume_unwind(p);
        }
    }
}

/// The subsystem worker task implementation
pub async fn subsystem<S, IF, SF, E>(
    full_name: String,
    subsys_init: IF,
    submit_handle: SubmitOnlyHandle<S::Interface>,
    mut action_rx: mpsc::UnboundedReceiver<Action<S::Interface>>,
    mut shutdown_rx: oneshot::Receiver<()>,
    shutting_down_tx: mpsc::UnboundedSender<()>,
) where
    IF: FnOnce(SubmitOnlyHandle<S::Interface>) -> SF + Send + 'static,
    SF: std::future::IntoFuture<Output = Result<S, E>> + Send,
    SF::IntoFuture: Send,
    S: Subsystem,
    E: std::error::Error,
{
    log::info!("Subsystem {full_name} starting");

    // Make sure that we send the shutdown signal even in case of a panic.
    let _shutdown_sender = OnceDestructor::new({
        let full_name = &full_name;
        move || {
            let _ = shutting_down_tx.send(());
            log::info!("Subsystem {full_name} terminated");
        }
    });

    // Worker task set to serve reads in parallel.
    let mut worker_tasks = JoinSet::new();

    // Initialize the subsystem.
    let subsys = match subsys_init(submit_handle).await {
        Ok(subsys) => Arc::new(RwLock::new(subsys)),
        Err(err) => {
            log::error!("Subsystem {full_name} failed to initialize: {err}");
            return;
        }
    };

    // Set up a closure to check whether a subsystem has some background work to do.
    let background_work_signal = || async {
        if !subsys.read().await.has_background_work() {
            std::future::pending().await
        }
    };

    let mut watchdog_state: Option<(
        Instant,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
        Arc<AtomicBool>,
        Arc<AtomicU8>,
    )> = None;
    if full_name.ends_with("/chainstate") {
        let start = Instant::now();
        let last_progress_ms = Arc::new(AtomicU64::new(0));
        let inflight_writes = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let current_write_kind = Arc::new(AtomicU8::new(CHAINSTATE_WRITE_KIND_NONE));
        let last_warn_ms = Arc::new(AtomicU64::new(0));
        let full_name_clone = full_name.clone();

        let last_progress_ms_watch = Arc::clone(&last_progress_ms);
        let inflight_writes_watch = Arc::clone(&inflight_writes);
        let running_watch = Arc::clone(&running);
        let current_write_kind_watch = Arc::clone(&current_write_kind);
        let last_warn_ms_watch = Arc::clone(&last_warn_ms);

        std::thread::spawn(move || {
            let warn_after_ms = CHAINSTATE_WATCHDOG_NO_PROGRESS_AFTER.as_millis() as u64;
            loop {
                std::thread::sleep(CHAINSTATE_WATCHDOG_POLL_INTERVAL);
                if !running_watch.load(Ordering::Relaxed) {
                    break;
                }
                if inflight_writes_watch.load(Ordering::Relaxed) == 0 {
                    continue;
                }
                let now_ms = start.elapsed().as_millis() as u64;
                let last_ms = last_progress_ms_watch.load(Ordering::Relaxed);
                let since_ms = now_ms.saturating_sub(last_ms);
                if since_ms >= warn_after_ms {
                    let last_warn = last_warn_ms_watch.load(Ordering::Relaxed);
                    if now_ms.saturating_sub(last_warn) >= warn_after_ms {
                        log::warn!(
                            "Subsystem {full_name_clone} no progress for {since_ms}ms (inflight writes: {}, write_kind: {})",
                            inflight_writes_watch.load(Ordering::Relaxed),
                            chainstate_write_kind_name(
                                current_write_kind_watch.load(Ordering::Relaxed),
                            ),
                        );
                        last_warn_ms_watch.store(now_ms, Ordering::Relaxed);
                    }
                }
            }
        });

        watchdog_state = Some((
            start,
            last_progress_ms,
            inflight_writes,
            running,
            current_write_kind,
        ));
    }

    log::info!("Subsystem {full_name} started");

    // Main event loop
    loop {
        tokio::select! {
            // Process events in pre-determined order.
            biased;

            // We're shutting down, no point in doing anything else.
            result = (&mut shutdown_rx) => {
                if let Err(err) = result {
                    log::error!("Shutdown channel for {full_name} closed prematurely: {err}");
                }
                if let Some((_, _, _, running, _)) = &watchdog_state {
                    running.store(false, Ordering::Relaxed);
                }
                break;
            }

            // Handle external call requests next.
            Some(call) = action_rx.recv() => {
                if let Some((start, last_progress_ms, inflight_writes, _, _)) = &watchdog_state {
                    last_progress_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                }
                match call {
                    Action::Mut(call) => {
                        if let Some((_, _, _, _, _)) = &watchdog_state {
                            let queued_ms = call.submitted_at.elapsed().as_millis() as u64;
                            if queued_ms >= CHAINSTATE_WATCHDOG_QUEUE_WARN_AFTER.as_millis() as u64 {
                                match call.label {
                                    Some(label) => {
                                        log::warn!(
                                            "Subsystem {full_name} mut call queued for {queued_ms}ms (label: {label})"
                                        );
                                    }
                                    None => {
                                        log::warn!(
                                            "Subsystem {full_name} mut call queued for {queued_ms}ms"
                                        );
                                    }
                                }
                            }
                        }
                        if let Some((_, _, inflight_writes, _, current_write_kind)) = &watchdog_state {
                            inflight_writes.fetch_add(1, Ordering::Relaxed);
                            current_write_kind
                                .store(CHAINSTATE_WRITE_KIND_ACTION_MUT, Ordering::Relaxed);
                        }
                        let mut write_guard = if watchdog_state.is_some() {
                            let wait_start = Instant::now();
                            let guard = subsys.write().await;
                            let wait = wait_start.elapsed();
                            if wait > CHAINSTATE_WATCHDOG_WRITE_LOCK_WARN_AFTER {
                                log::warn!(
                                    "Subsystem {full_name} write lock wait {:?} (>{:?}, write_kind: {})",
                                    wait,
                                    CHAINSTATE_WATCHDOG_WRITE_LOCK_WARN_AFTER,
                                    chainstate_write_kind_name(CHAINSTATE_WRITE_KIND_ACTION_MUT),
                                );
                            }
                            guard
                        } else {
                            subsys.write().await
                        };
                        (call.func)(write_guard.interface_mut()).await;
                        if let Some((_, _, inflight_writes, _, current_write_kind)) = &watchdog_state {
                            inflight_writes.fetch_sub(1, Ordering::Relaxed);
                            current_write_kind
                                .store(CHAINSTATE_WRITE_KIND_NONE, Ordering::Relaxed);
                        }
                        if let Some((start, last_progress_ms, _, _, _)) = &watchdog_state {
                            last_progress_ms
                                .store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                        }
                    },
                    Action::Ref(call) => {
                        if let Some((_, _, _, _, _)) = &watchdog_state {
                            let queued_ms = call.submitted_at.elapsed().as_millis() as u64;
                            if queued_ms >= CHAINSTATE_WATCHDOG_QUEUE_WARN_AFTER.as_millis() as u64 {
                                match call.label {
                                    Some(label) => {
                                        log::warn!(
                                            "Subsystem {full_name} ref call queued for {queued_ms}ms (label: {label})"
                                        );
                                    }
                                    None => {
                                        log::warn!(
                                            "Subsystem {full_name} ref call queued for {queued_ms}ms"
                                        );
                                    }
                                }
                            }
                        }
                        let subsys = Arc::clone(&subsys);
                        worker_tasks.spawn(async move {
                            (call.func)(subsys.read().await.interface_ref()).await
                        }.in_current_span());
                        if let Some((start, last_progress_ms, _, _, _)) = &watchdog_state {
                            last_progress_ms
                                .store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                        }
                    },
                }
            }

            // Clean up worker tasks.
            Some(task_result) = worker_tasks.join_next() => {
                handle_result(&full_name, "worker", task_result);
            }

            // Finally, if nothing else is going on, process a unit of background work.
            () = background_work_signal() => {
                if let Some((start, last_progress_ms, inflight_writes, _, current_write_kind)) = &watchdog_state {
                    last_progress_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                    inflight_writes.fetch_add(1, Ordering::Relaxed);
                    current_write_kind.store(CHAINSTATE_WRITE_KIND_BACKGROUND, Ordering::Relaxed);
                }
                if watchdog_state.is_some() {
                    let wait_start = Instant::now();
                    let mut guard = subsys.write().await;
                    let wait = wait_start.elapsed();
                    if wait > CHAINSTATE_WATCHDOG_WRITE_LOCK_WARN_AFTER {
                        log::warn!(
                            "Subsystem {full_name} write lock wait {:?} (>{:?}, write_kind: {})",
                            wait,
                            CHAINSTATE_WATCHDOG_WRITE_LOCK_WARN_AFTER,
                            chainstate_write_kind_name(CHAINSTATE_WRITE_KIND_BACKGROUND),
                        );
                    }
                    guard.perform_background_work_unit();
                } else {
                    subsys.write().await.perform_background_work_unit();
                }
                if let Some((start, last_progress_ms, inflight_writes, _, current_write_kind)) = &watchdog_state {
                    last_progress_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                    inflight_writes.fetch_sub(1, Ordering::Relaxed);
                    current_write_kind.store(CHAINSTATE_WRITE_KIND_NONE, Ordering::Relaxed);
                }
            }
        }
    }

    if let Some((_, _, _, running, _)) = &watchdog_state {
        running.store(false, Ordering::Relaxed);
    }

    while let Some(task_result) = worker_tasks.join_next().await {
        handle_result(&full_name, "worker", task_result);
    }

    // All worker tasks have terminated above, we are the last ones holding the subsys Arc
    let subsys = Arc::try_unwrap(subsys)
        .map_err(|_| ())
        .expect("Something else still holds the subsystem reference");
    RwLock::into_inner(subsys).shutdown().await;
}

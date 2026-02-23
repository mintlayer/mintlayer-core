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

use std::future::IntoFuture;

use tokio::{
    sync::{mpsc, oneshot, RwLock},
    task::JoinSet,
};
use tracing::Instrument;

use logging::log;
use utils::{once_destructor::OnceDestructor, sync::Arc, tokio_spawn_in_join_set};

use crate::{calls::Action, Subsystem};

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
pub async fn subsystem<S, SF, E>(
    full_name: String,
    subsys_fut: SF,
    mut action_rx: mpsc::UnboundedReceiver<Action<S::Interface>>,
    mut task_shutdown_trigger_rx: oneshot::Receiver<()>,
    task_shut_down_tx: mpsc::UnboundedSender<()>,
) where
    SF: IntoFuture<Output = Result<S, E>> + Send,
    SF::IntoFuture: Send,
    S: Subsystem,
    E: std::error::Error,
{
    log::info!("Subsystem {full_name} starting");

    // Make sure that we send the shutdown signal even in case of a panic.
    let _shutdown_sender = OnceDestructor::new({
        let full_name = &full_name;
        move || {
            let _ = task_shut_down_tx.send(());
            log::info!("Subsystem {full_name} terminated");
        }
    });

    // Worker task set to serve reads in parallel.
    let mut worker_tasks = JoinSet::new();

    // Initialize the subsystem.
    let subsys = match subsys_fut.await {
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

    log::info!("Subsystem {full_name} started");

    // Main event loop
    loop {
        tokio::select! {
            // Process events in pre-determined order.
            biased;

            // We're shutting down, no point in doing anything else.
            result = (&mut task_shutdown_trigger_rx) => {
                if let Err(err) = result {
                    log::error!("Shutdown channel for {full_name} closed prematurely: {err}");
                }
                break;
            }

            // Handle external call requests next.
            Some(call) = action_rx.recv() => {
                match call {
                    Action::Mut(call) => {
                        call(subsys.write().await.interface_mut()).await
                    },
                    Action::Ref(call) => {
                        let subsys = Arc::clone(&subsys);
                        tokio_spawn_in_join_set(
                            &mut worker_tasks,
                            async move {
                                call(subsys.read().await.interface_ref()).await
                            }.in_current_span(),
                            &format!("{full_name}'s Action::Ref"),
                        );
                    },
                }
            }

            // Clean up worker tasks.
            Some(task_result) = worker_tasks.join_next() => {
                handle_result(&full_name, "worker", task_result);
            }

            // Finally, if nothing else is going on, process a unit of background work.
            () = background_work_signal() => {
                subsys.write().await.perform_background_work_unit();
            }
        }
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

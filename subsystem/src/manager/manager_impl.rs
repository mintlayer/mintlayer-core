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

use std::{panic, time::Duration};

use futures::future::BoxFuture;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

use logging::log;
use utils::{
    const_value::ConstValue, set_flag::SetFlag, shallow_clone::ShallowClone,
    tokio_spawn_in_current_tracing_span, tokio_spawn_in_tracing_span,
};

use crate::{task, wrappers, Handle, ManagerConfig, SubmitOnlyHandle, Subsystem};

use super::shutdown_signal::shutdown_signal;

/// Top-level subsystem manager.
///
/// An application is composed of a number of long-lived subsystems. The [Manager] type starts
/// and manages the life cycle of the subsystems. Whenever a subsystem exits, all other subsystems
/// are requested to terminate and the manager is shut down.
#[must_use]
pub struct Manager {
    // Manager configuration
    config: ConstValue<ManagerConfig>,

    // The channel through which the shutdown may be initiated.
    // Its sender is exposed to external callers via `ShutdownTrigger` and also passed to each
    // subsystem task as the "task_shut_down_tx" parameter, so that when the subsystem is shut down
    // for any reason (including a panic), the general shutdown is initiated as well.
    shutdown_trigger_tx: mpsc::UnboundedSender<()>,
    shutdown_trigger_rx: mpsc::UnboundedReceiver<()>,

    // A watch channel (a shared flag) through which the manager can notify the actual subsystems
    // that the general shutdown has been initiated (so that they can abort long-running blocking
    // calls, for example).
    // Note:
    // 1) We can't re-use subsystem's own "task shutdown channel" (whose receiver is held
    // in `SubsystemData`) for the purpose of blocking calls cancellation, because the blocking call
    // may need to be cancelled before this particular subsystem's shutdown has been initiated
    // (e.g. if another subsystem that is shut down earlier needs this one to unblock first).
    // 2) We could technically "combine" `shutdown_trigger` and `shutdown_initiated` into one
    // channel, but this would probably complicate things instead of simplifying them.
    shutdown_initiated_tx: watch::Sender<SetFlag>,
    shutdown_initiated_rx: watch::Receiver<SetFlag>,

    // List of subsystem tasks
    subsystems: Vec<SubsystemData<BoxFuture<'static, ()>>>,
}

impl Manager {
    /// Initialize a new subsystem manager using default configuration.
    pub fn new(name: &'static str) -> Self {
        Self::new_with_config(ManagerConfig::new(name))
    }

    /// Initialize a new subsystem manager.
    pub fn new_with_config(config: ManagerConfig) -> Self {
        log::info!("Initializing subsystem manager {}", config.name);

        let (shutdown_trigger_tx, shutdown_trigger_rx) = mpsc::unbounded_channel();
        let (shutdown_initiated_tx, shutdown_initiated_rx) = watch::channel(SetFlag::new());
        let subsystems = Vec::new();

        Self {
            config: config.into(),
            shutdown_trigger_tx,
            shutdown_trigger_rx,
            shutdown_initiated_tx,
            shutdown_initiated_rx,
            subsystems,
        }
    }

    /// Add a subsystem with a custom initialization routine.
    ///
    /// This method allows you to set up the subsystem in a custom way using an asynchronous
    /// initialization routine. The routine should return the subsystem state object, which has to
    /// implement the [Subsystem] trait. The initialization routine is also given access to a
    /// send-only handle to the subsystem itself, which can be used to register the subsystem into
    /// various event handlers, and a shutdown flag, which can be used to cancel long-running
    /// synchronous tasks if a shutdown has been initiated.
    pub fn add_custom_subsystem<S, IF, SF, E>(
        &mut self,
        subsys_name: &'static str,
        subsys_init: IF,
    ) -> Handle<S::Interface>
    where
        IF: FnOnce(
                SubmitOnlyHandle<S::Interface>,
                /*shutdown initiated*/ watch::Receiver<SetFlag>,
            ) -> SF
            + Send
            + 'static,
        SF: std::future::IntoFuture<Output = Result<S, E>> + Send + 'static,
        SF::IntoFuture: Send,
        S: Subsystem,
        E: std::error::Error + 'static,
    {
        let full_name = self.config.full_name_of(subsys_name);

        // The channel through which the manager will initiate the shutdown of this particular
        // subsystem's task.
        let (task_shutdown_trigger_tx, task_shutdown_trigger_rx) = oneshot::channel();

        // Action channel
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let submit_handle = SubmitOnlyHandle::new(action_tx);

        log::info!("Registering subsystem {full_name}");

        let subsys_future = subsys_init(
            submit_handle.shallow_clone(),
            self.shutdown_initiated_rx.clone(),
        );
        let task_future = Box::pin(task::subsystem(
            full_name.clone(),
            subsys_future,
            action_rx,
            task_shutdown_trigger_rx,
            self.shutdown_trigger_tx.clone(),
        ));

        self.subsystems.push(SubsystemData {
            full_name,
            task: task_future,
            task_shutdown_tx: task_shutdown_trigger_tx,
        });

        Handle::new(submit_handle)
    }

    /// Add a subsystem that does not require custom initialization code.
    pub fn add_subsystem<S>(&mut self, name: &'static str, subsys: S) -> Handle<S::Interface>
    where
        S: Send + Sync + Subsystem + 'static,
    {
        self.add_custom_subsystem(name, move |_, _| async {
            Result::<S, std::convert::Infallible>::Ok(subsys)
        })
    }

    /// Add a subsystem. Use the provided object directly as the subsystem state object.
    pub fn add_direct_subsystem<S>(&mut self, name: &'static str, subsys: S) -> Handle<S>
    where
        S: Send + Sync + 'static,
    {
        self.add_subsystem(name, wrappers::Direct::new(subsys))
    }

    /// Create a trigger object that can be used to shut down the system
    pub fn make_shutdown_trigger(&self) -> ShutdownTrigger {
        ShutdownTrigger::new(&self.shutdown_trigger_tx)
    }

    /// Run the application main task.
    ///
    /// Completes when all the subsystems are fully shut down.
    pub async fn main(self) {
        let manager_name = self.config.name;
        log::info!("Manager {manager_name} starting subsystems");

        // Run all the subsystem tasks.
        let subsystems = self
            .subsystems
            .into_iter()
            .map(|subsys_data| {
                subsys_data.map_task(|fut, subsys_full_name| {
                    tokio_spawn_in_current_tracing_span(fut, subsys_full_name)
                })
            })
            .collect::<Vec<_>>();

        // Drop the shutdown trigger sender to ensure that the manager won't wait for itself
        // (e.g. if no subsystems were registered or if they somehow exited without sending
        // a shutdown trigger, though the latter should not be possible at this moment).
        drop(self.shutdown_trigger_tx);

        // Wait for the shutdown trigger.
        match shutdown_signal(self.shutdown_trigger_rx, self.config.enable_signal_handlers).await {
            Ok(reason) => log::info!("Manager {manager_name} shutting down: {reason}"),
            Err(err) => log::error!("Manager {manager_name} shutting down: {err}"),
        }

        // Set the "shutdown initiated" flag so that subsystems that perform long-running blocking
        // calls could cancel whatever they're doing.
        self.shutdown_initiated_tx.send_modify(|flag| flag.set());

        // Shut down the subsystems in the reverse order of creation.
        for subsys in subsystems.into_iter().rev() {
            subsys.shutdown(self.config.shutdown_timeout_per_subsystem).await;
        }

        log::info!("Manager {manager_name} terminated");
    }

    /// Runs the application in a separate task.
    ///
    /// This method should always be used instead of spawning a task manually because it prevents
    /// incorrect usage. The returned handle must be joined to ensure a proper subsystems
    /// shutdown.
    pub fn main_in_task(self) -> ManagerJoinHandle {
        let handle = Some(tokio_spawn_in_current_tracing_span(
            async move { self.main().await },
            "Subsystem mgr",
        ));
        ManagerJoinHandle { handle }
    }

    /// Runs the application in a separate task.
    ///
    /// This does the same as `main_in_task` but uses the specified tracing span instead of
    /// the current one.
    pub fn main_in_task_in_tracing_span(self, tracing_span: tracing::Span) -> ManagerJoinHandle {
        let handle = Some(tokio_spawn_in_tracing_span(
            async move { self.main().await },
            tracing_span,
            "Subsystem mgr",
        ));
        ManagerJoinHandle { handle }
    }
}

/// Information about each subsystem stored by the manager
struct SubsystemData<T> {
    full_name: String,
    task_shutdown_tx: oneshot::Sender<()>,
    task: T,
}

impl<T> SubsystemData<T> {
    fn map_task<U>(self, f: impl FnOnce(T, /*full_name*/ &str) -> U) -> SubsystemData<U> {
        let Self {
            full_name,
            task_shutdown_tx,
            task,
        } = self;
        let task = f(task, &full_name);
        SubsystemData {
            full_name,
            task_shutdown_tx,
            task,
        }
    }
}

impl SubsystemData<JoinHandle<()>> {
    async fn shutdown(self, timeout: Option<Duration>) {
        let full_name = self.full_name;

        if let Err(()) = self.task_shutdown_tx.send(()) {
            log::warn!("Subsystem {full_name} is already down");
        }

        let shutdown_future =
            async { task::handle_result(&full_name, "top-level", self.task.await) };

        if let Some(timeout) = timeout {
            cfg_if::cfg_if! {
                if #[cfg(all(feature = "time", not(loom)))] {
                    // Wait for shutdown under a timeout.
                    if tokio::time::timeout(timeout, shutdown_future).await.is_err() {
                        log::error!("Subsystem {full_name} shutdown timed out");
                    }
                } else {
                    // Timeout was requested but is not supported
                    if cfg!(not(feature = "time")) {
                        log::error!("Shutdown timeout support not compiled in");
                    } else if cfg!(loom) {
                        log::warn!("Shutdown timeout disabled under loom");
                    }
                    shutdown_future.await
                }
            }
        } else {
            // No timeout requested, just wait for shutdown
            shutdown_future.await
        };
    }
}

/// Used to initiate shutdown of manager and subsystems.
#[derive(Clone)]
pub struct ShutdownTrigger(mpsc::WeakUnboundedSender<()>);

impl ShutdownTrigger {
    fn new(sender: &mpsc::UnboundedSender<()>) -> Self {
        Self(sender.downgrade())
    }

    /// Initiate shutdown
    pub fn initiate(self) {
        match self.0.upgrade().map(|s| s.send(())) {
            None | Some(Err(mpsc::error::SendError(_))) => {
                log::info!("Shutdown requested but the system is already down")
            }
            Some(Ok(())) => {}
        }
    }
}

/// Join handle for the top-level subsystem manager task
pub struct ManagerJoinHandle {
    handle: Option<JoinHandle<()>>,
}

impl ManagerJoinHandle {
    pub async fn join(mut self) {
        if let Err(err) = self.handle.take().expect("The join handle is missing").await {
            log::error!("Failed to join subsystem manager handle: {err:?}");
        }
    }
}

impl Drop for ManagerJoinHandle {
    fn drop(&mut self) {
        if self.handle.is_none() {
            return;
        }

        if std::thread::panicking() {
            log::error!("Subsystem manager's handle hasn't been joined");
        } else {
            panic!("Subsystem manager's handle hasn't been joined")
        }
    }
}

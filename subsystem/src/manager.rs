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

use core::{future::Future, time::Duration};
use std::{panic, sync::Arc};

use futures::future::BoxFuture;
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    task::{JoinHandle, JoinSet},
};
use tracing::Instrument;

use logging::log;
use utils::once_destructor::OnceDestructor;

use crate::subsystem::{Action, CallRequest, Handle, ShutdownRequest, Subsystem, SubsystemConfig};

/// Manager configuration options.
pub struct ManagerConfig {
    /// Subsystem manager name
    name: &'static str,
    /// Shutdown timeout. Set to `None` for no (i.e. unlimited) timeout.
    shutdown_timeout_per_subsystem: Option<Duration>,
}

impl ManagerConfig {
    /// Default shutdown timeout.
    const DEFAULT_SHUTDOWN_TIMEOUT: Option<Duration> = if cfg!(all(feature = "time", not(loom))) {
        Some(Duration::from_secs(30))
    } else {
        None
    };

    /// New config using given subsystem name. Other options are default.
    pub fn named(name: &'static str) -> Self {
        Self::new(name, Self::DEFAULT_SHUTDOWN_TIMEOUT)
    }

    pub fn new(name: &'static str, shutdown_timeout_per_subsystem: Option<Duration>) -> Self {
        Self {
            name,
            shutdown_timeout_per_subsystem,
        }
    }
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            name: "<manager>",
            shutdown_timeout_per_subsystem: Self::DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }
}

/// Top-level subsystem manager.
///
/// An application is composed of a number of long-lived subsystems. The [Manager] type starts
/// and manages the life cycle of the subsystems. Whenever a subsystem exits, all other subsystems
/// are requested to terminate and the manager is shut down.
#[must_use]
pub struct Manager {
    // Manager name
    name: &'static str,

    // Shutdown timeout settings
    shutdown_timeout_per_subsystem: Option<Duration>,

    // Used by a subsystem to notify the manager it is shutting down. This is taken as a command
    // for all subsystems to shut down. Shutdown completion is detected by all senders having closed
    // this channel.
    shutting_down_tx: mpsc::UnboundedSender<()>,
    shutting_down_rx: mpsc::UnboundedReceiver<()>,

    // List of subsystem tasks
    subsystems: Vec<SubsystemInfo>,
}

struct SubsystemInfo {
    name: &'static str,
    task: BoxFuture<'static, ()>,
    shutdown_tx: oneshot::Sender<()>,
}

impl Manager {
    /// Initialize a new subsystem manager.
    pub fn new(name: &'static str) -> Self {
        Self::new_with_config(ManagerConfig::named(name))
    }

    /// Initialize a new subsystem manager.
    pub fn new_with_config(config: ManagerConfig) -> Self {
        let ManagerConfig {
            name,
            shutdown_timeout_per_subsystem,
        } = config;
        log::info!("Initializing subsystem manager {}", name);

        let (shutting_down_tx, shutting_down_rx) = mpsc::unbounded_channel();
        let subsystems = Vec::new();

        Self {
            name,
            shutting_down_tx,
            shutting_down_rx,
            shutdown_timeout_per_subsystem,
            subsystems,
        }
    }

    /// Add a raw subsystem.
    ///
    /// Gives full control over how shutdown and call requests are handled. If this is not
    /// required, use [Manager::add_subsystem] instead. A subsystem has to handle shutdown and call
    /// requests. It can also react to external IO events. If the subsystem handles *only* calls
    /// and shutdown requests without interaction with any additional IO and does not need custom
    /// shutdown logic, use [Manager::add_subsystem].
    ///
    /// A typical skeleton of a subsystem looks like this:
    /// ```no_run
    /// # let mut manager = subsystem::Manager::new("app");
    /// let subsystem = manager.add_subsystem_with_custom_eventloop(
    ///     "my-subsys",
    ///     |mut call, mut shutdown| async move {
    ///         loop {
    ///             tokio::select! {
    ///                 // Shutdown received, break out of the loop.
    ///                 () = shutdown.recv() => { break; }
    ///                 // Handle calls. An object representing the subsystem is passed in.
    ///                 // Note this does not exploit the distinction between `call` and `call_mut`.
    ///                 func = call.recv() => {
    ///                     func.handle_call_mut(todo!("put an argument here"));
    ///                 }
    ///                 // Handle any other IO events here
    ///             };
    ///         }
    ///     },
    /// );
    /// # let _ = subsystem.call(|()| ());  // Fix the call type to avoid ambiguity.
    /// ```
    pub fn add_raw_subsystem_with_config<T, F, S>(
        &mut self,
        config: SubsystemConfig,
        subsystem: S,
    ) -> Handle<T>
    where
        T: 'static + Send + Sync + ?Sized,
        F: 'static + Send + Future<Output = ()>,
        S: 'static + Send + FnOnce(CallRequest<T>, ShutdownRequest) -> F,
    {
        // Name strings
        let manager_name = self.name;
        let subsys_name = config.subsystem_name;

        // Shutdown-related channels
        let shutting_down_tx = self.shutting_down_tx.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown_rq = ShutdownRequest(shutdown_rx);
        // Call related channels
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let call_rq = CallRequest(action_rx);

        let task = Box::pin(async move {
            log::info!("Subsystem {}/{} started", manager_name, subsys_name);

            // Make sure that we send the shutdown signal even in case of a panic.
            let _shutdown_sender = OnceDestructor::new(|| {
                let _ = shutting_down_tx.send(());

                log::info!("Subsystem {}/{} terminated", manager_name, subsys_name);

                // Close the channel to signal the completion of the shutdown.
                drop(shutting_down_tx);
            });

            // Perform the subsystem task.
            subsystem(call_rq, shutdown_rq).await;
        });
        self.subsystems.push(SubsystemInfo {
            name: subsys_name,
            task,
            shutdown_tx,
        });

        log::info!("Subsystem {}/{} initialized", manager_name, subsys_name);

        Handle::new(action_tx)
    }

    /// Add a passive subsystem.
    ///
    /// A passive subsystem does not interact with the environment on its own. It only serves calls
    /// from other subsystems. A hook to be invoked on shutdown can be specified by means of the
    /// [Subsystem] trait.
    pub fn add_subsystem_with_config<S: Subsystem>(
        &mut self,
        config: SubsystemConfig,
        subsys: S,
    ) -> Handle<S> {
        let manager_name = self.name;
        let subsys_name = config.subsystem_name;

        self.add_raw_subsystem_with_config(config, move |mut call_rq, mut shutdown_rq| async move {
            let mut worker_tasks = JoinSet::new();
            let subsys = Arc::new(RwLock::new(subsys));

            loop {
                tokio::select! {
                    () = shutdown_rq.recv() => { break; }
                    call = call_rq.recv() => {
                        let subsys = Arc::clone(&subsys);
                        match call {
                            Action::Mut(call) => {
                                worker_tasks.spawn(async move {
                                    let mut subsys = subsys.write().await;
                                    call(&mut *subsys).await
                                }.in_current_span());
                            },
                            Action::Ref(call) => {
                                worker_tasks.spawn(async move {
                                    let subsys = subsys.read().await;
                                    call(&*subsys).await
                                }.in_current_span());
                            },
                        }
                    }
                    Some(task_result) = worker_tasks.join_next() => {
                        Self::handle_task_result(manager_name, subsys_name, "worker", task_result);
                    }
                }
            }

            while let Some(task_result) = worker_tasks.join_next().await {
                Self::handle_task_result(manager_name, subsys_name, "worker", task_result);
            }

            // All worker tasks have terminated above, we are the last ones holding the subsys Arc
            let subsys = Arc::try_unwrap(subsys)
                .map_err(|_| ())
                .expect("Something else still holds the subsystem reference");
            RwLock::into_inner(subsys).shutdown().await;
        })
    }

    /// Add a raw subsystem. See [Manager::add_raw_subsystem_with_config].
    pub fn add_subsystem_with_custom_eventloop<T, F, S>(
        &mut self,
        name: &'static str,
        subsystem: S,
    ) -> Handle<T>
    where
        T: 'static + Send + Sync + ?Sized,
        F: 'static + Send + Future<Output = ()>,
        S: 'static + Send + FnOnce(CallRequest<T>, ShutdownRequest) -> F,
    {
        self.add_raw_subsystem_with_config(SubsystemConfig::named(name), subsystem)
    }

    /// Add a passive subsystem. See [Manager::add_subsystem_with_config].
    pub fn add_subsystem<S: Subsystem>(&mut self, name: &'static str, subsys: S) -> Handle<S> {
        self.add_subsystem_with_config(SubsystemConfig::named(name), subsys)
    }

    /// Install termination signal handlers.
    ///
    /// This adds a subsystem that listens for the Ctrl-C signal and exits once it is received,
    /// signalling all other subsystems and the whole manager to shut down.
    #[cfg(not(loom))]
    pub fn install_signal_handlers(&mut self) {
        self.add_subsystem_with_custom_eventloop(
            "ctrl-c",
            |mut call_rq: CallRequest<()>, mut shutdown_rq| async move {
                // Gracefully handle SIGTERM on *nix
                #[cfg(unix)]
                let term_signal = async move {
                    let mut signal =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("Signal handler failed unexpectedly");
                    signal.recv().await;
                };
                #[cfg(not(unix))]
                let term_signal = std::future::pending();

                tokio::select! {
                    ctrl_c_signal = tokio::signal::ctrl_c() => {
                        if let Err(e) = ctrl_c_signal {
                            log::error!("Ctrl-C signal handler failed: {e}");
                        } else {
                            log::info!("Ctrl-C signal received");
                        }
                    }
                    _ = term_signal => {
                        log::info!("Terminate signal received");
                    }
                    () = shutdown_rq.recv() => {},
                    call = call_rq.recv() => {
                        match call {
                            Action::Ref(call) => call(&()).await,
                            Action::Mut(call) => call(&mut ()).await,
                        }
                    }
                }
            },
        );
    }

    /// Create a trigger object that can be used to shut down the system
    pub fn make_shutdown_trigger(&self) -> ShutdownTrigger {
        ShutdownTrigger(self.shutting_down_tx.downgrade())
    }

    /// Run the application main task.
    ///
    /// Completes when all the subsystems are fully shut down.
    pub async fn main(mut self) {
        log::info!("Manager {} starting subsystems", self.name);

        // Run all the subsystem tasks.
        let subsystems: Vec<_> = self
            .subsystems
            .into_iter()
            .map(|s| {
                (
                    s.name,
                    logging::spawn_in_current_span(s.task),
                    s.shutdown_tx,
                )
            })
            .collect();

        // Signal the manager is shut down so it does not wait for itself
        drop(self.shutting_down_tx);

        // Wait for the shutdown trigger.
        if self.shutting_down_rx.recv().await.is_none() {
            log::warn!("Manager {}: all subsystems already down", self.name);
        }
        log::info!("Manager {} shutting down", self.name);
        // Drop the receiver in order to prevent blocking of subsystems.
        drop(self.shutting_down_rx);

        // Shut down the subsystems in the reverse order of creation.
        for (name, handle, shutdown_tx) in subsystems.into_iter().rev() {
            if let Err(()) = shutdown_tx.send(()) {
                log::warn!("Manager {}: {name} subsystem is already down", self.name);
            }

            Self::wait_for_subsystem_shutdown(
                self.name,
                name,
                self.shutdown_timeout_per_subsystem,
                handle,
            )
            .await;
        }

        log::info!("Manager {} terminated", self.name);
    }

    fn handle_task_result(
        manager_name: &str,
        subsys_name: &str,
        task_type: &str,
        res: Result<(), tokio::task::JoinError>,
    ) {
        log::trace!("Manager {manager_name}: {subsys_name} {task_type} task finished");
        if let Err(err) = res {
            log::error!(
                "Manager {manager_name}: failed to join the {subsys_name} {task_type} task: {err}"
            );
            if let Ok(p) = err.try_into_panic() {
                panic::resume_unwind(p);
            }
        }
    }

    async fn wait_for_shutdown(manager_name: &str, subsystem_name: &str, handle: JoinHandle<()>) {
        Self::handle_task_result(manager_name, subsystem_name, "top-level", handle.await)
    }

    async fn wait_for_subsystem_shutdown(
        manager_name: &str,
        subsystem_name: &str,
        timeout: Option<Duration>,
        handle: JoinHandle<()>,
    ) {
        let shutdown_future = Self::wait_for_shutdown(manager_name, subsystem_name, handle);

        if let Some(timeout) = timeout {
            cfg_if::cfg_if! {
                if #[cfg(all(feature = "time", not(loom)))] {
                    // Wait for shutdown under a timeout.
                    if tokio::time::timeout(timeout, shutdown_future).await.is_err() {
                        log::error!("Manager {manager_name}: subsystem {subsystem_name} shutdown timed out");
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

    /// Runs the application in a separate task.
    ///
    /// This method should always be used instead of spawning a task manually because it prevents
    /// an incorrect usage. The returned handle must be joined to ensure a proper subsystems
    /// shutdown.
    pub fn main_in_task(self) -> ManagerJoinHandle {
        let handle = Some(logging::spawn_in_current_span(
            async move { self.main().await },
        ));
        ManagerJoinHandle { handle }
    }
}

/// Used to initiate shutdown of manager and subsystems.
#[derive(Clone)]
pub struct ShutdownTrigger(mpsc::WeakUnboundedSender<()>);

impl ShutdownTrigger {
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

pub struct ManagerJoinHandle {
    handle: Option<JoinHandle<()>>,
}

impl ManagerJoinHandle {
    pub async fn join(mut self) {
        if let Err(e) = self.handle.take().expect("The join handle is missing").await {
            log::error!("Failed to join handle: {e:?}");
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

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(all(feature = "time", not(loom)))]
    #[tokio::test]
    async fn shutdown_timeout() {
        testing_logger::setup();

        let mut man = Manager::new_with_config(ManagerConfig {
            name: "timeout_test",
            shutdown_timeout_per_subsystem: Some(Duration::from_secs(1)),
        });

        man.add_subsystem_with_custom_eventloop(
            "does_not_want_to_exit",
            |_call_rq: CallRequest<()>, _shut_rq| std::future::pending(),
        );
        man.make_shutdown_trigger().initiate();
        man.main().await;

        testing_logger::validate(|logs| {
            assert!(logs.iter().any(|entry| entry.body.contains("shutdown timed out")));
        });
    }
}

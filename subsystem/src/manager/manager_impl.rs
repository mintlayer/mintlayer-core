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
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use logging::log;
use utils::{const_value::ConstValue, shallow_clone::ShallowClone};

use crate::{task, Handle, ManagerConfig, SubmitOnlyHandle, Subsystem};

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

    // Used by a subsystem to notify the manager it is shutting down. This is taken as a command
    // for all subsystems to shut down. Shutdown completion is detected by all senders having closed
    // this channel.
    shutting_down_tx: mpsc::UnboundedSender<()>,
    shutting_down_rx: mpsc::UnboundedReceiver<()>,

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
        let (shutting_down_tx, shutting_down_rx) = mpsc::unbounded_channel();
        let subsystems = Vec::new();

        Self {
            config: config.into(),
            shutting_down_tx,
            shutting_down_rx,
            subsystems,
        }
    }

    /// Add a subsystem with a custom initialization routine.
    ///
    /// This method allows you to set up the subsystem in a custom way using an asynchronous
    /// initialization routine. The routine should return the subsystem state object, which has to
    /// implement the [Subsystem] trait. The initialization routine is also given access to a
    /// send-only handle to the subsystem itself. It can be used to register the subsystem into
    /// various event handlers.
    pub fn add_custom_subsystem<S, IF, SF, E>(
        &mut self,
        subsys_name: &'static str,
        subsys_init: IF,
    ) -> Handle<S::Interface>
    where
        IF: FnOnce(SubmitOnlyHandle<S::Interface>) -> SF + Send + 'static,
        SF: std::future::IntoFuture<Output = Result<S, E>> + Send + 'static,
        SF::IntoFuture: Send,
        S: Subsystem,
        E: std::error::Error + 'static,
    {
        let full_name = self.config.full_name_of(subsys_name);

        // Shutdown-related channels
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // Call related channels
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let submit_handle = SubmitOnlyHandle::new(action_tx);

        log::info!("Registering subsystem {full_name}");

        let task = Box::pin(task::subsystem(
            full_name.clone(),
            subsys_init,
            submit_handle.shallow_clone(),
            action_rx,
            shutdown_rx,
            self.shutting_down_tx.clone(),
        ));

        self.subsystems.push(SubsystemData {
            full_name,
            task,
            shutdown_tx,
        });

        Handle::new(submit_handle)
    }

    /// Add a subsystem that does not require custom initialization code.
    pub fn add_subsystem<S>(&mut self, name: &'static str, subsys: S) -> Handle<S::Interface>
    where
        S: 'static + Send + Sync + Subsystem,
    {
        self.add_custom_subsystem(name, move |_| async {
            Result::<S, std::convert::Infallible>::Ok(subsys)
        })
    }

    /// Add a subsystem. Use the provided object directly as the subsystem state object.
    pub fn add_direct_subsystem<S>(&mut self, name: &'static str, subsys: S) -> Handle<S>
    where
        S: 'static + Send + Sync,
    {
        self.add_subsystem(name, crate::wrappers::Direct::new(subsys))
    }

    /// Create a trigger object that can be used to shut down the system
    pub fn make_shutdown_trigger(&self) -> ShutdownTrigger {
        ShutdownTrigger::new(&self.shutting_down_tx)
    }

    /// Run the application main task.
    ///
    /// Completes when all the subsystems are fully shut down.
    pub async fn main(self) {
        let manager_name = self.config.name;
        log::info!("Manager {manager_name} starting subsystems");

        // Run all the subsystem tasks.
        let subsystems: Vec<_> = self
            .subsystems
            .into_iter()
            .map(|s| s.map_task(logging::spawn_in_current_span))
            .collect();

        // Signal the manager is shut down so it does not wait for itself
        drop(self.shutting_down_tx);

        // Wait for the shutdown trigger.
        match shutdown_signal(self.shutting_down_rx, self.config.enable_signal_handlers).await {
            Ok(reason) => log::info!("Manager {manager_name} shutting down: {reason}"),
            Err(err) => log::error!("Manager {manager_name} shutting down: {err}"),
        }

        // Shut down the subsystems in the reverse order of creation.
        for subsys in subsystems.into_iter().rev() {
            subsys.shutdown(self.config.shutdown_timeout_per_subsystem).await;
        }

        log::info!("Manager {manager_name} terminated");
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

/// Information about each subsystem stored by the manager
struct SubsystemData<T> {
    full_name: String,
    shutdown_tx: oneshot::Sender<()>,
    task: T,
}

impl<T> SubsystemData<T> {
    fn map_task<U>(self, f: impl FnOnce(T) -> U) -> SubsystemData<U> {
        let Self {
            full_name,
            shutdown_tx,
            task,
        } = self;
        SubsystemData {
            full_name,
            shutdown_tx,
            task: f(task),
        }
    }
}

impl SubsystemData<JoinHandle<()>> {
    async fn shutdown(self, timeout: Option<Duration>) {
        let full_name = self.full_name;

        if let Err(()) = self.shutdown_tx.send(()) {
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

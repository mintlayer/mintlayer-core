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

//! General framework for working with subsystems
//!
//! The [Manager] type handles a collection of [Subsystem]s. The framework also takes care of
//! inter-subsystem calls and clean shutdown.
//!
//! ## Calls
//!
//! Calls are dispatched by sending a closure over a channel to the subsystem. The subsystem then
//! sends the result back using a oneshot channel. The channel is awaited to emulate synchronous
//! calls.
//!
//! ## Shutdown sequence
//!
//! The shutdown proceeds in three phases:
//!
//! 1. As soon as any subsystem terminates, the main task is notified.
//! 2. The main task broadcasts the shutdown request to all subsystems. The subsystems react to the
//!    request by shutting themselves down.
//! 3. The main task waits for all subsystems to terminate.

use std::future::Future;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task;

use logging::log;

/// Top-level subsystem manager.
///
/// An application is composed of a number of long-lived subsystems. The [Manager] type starts
/// and manages the life cycle of the subsystems. Whenever a subsystem exits, all other subsystems
/// are requested to terminate and the manager is shut down.
pub struct Manager {
    // Manager name
    name: &'static str,

    // Used by the manager to order all subsystems to shut down.
    shutdown_request_tx: broadcast::Sender<()>,

    // Used by a subsystem to notify the manager it is shutting down. This is taken as a command
    // for all subsystems to shut down. Shutdown completion is detected by all senders having closed
    // this channel.
    shutting_down_tx: mpsc::Sender<()>,
    shutting_down_rx: mpsc::Receiver<()>,
}

impl Manager {
    /// Initialise a new subsystem manager.
    pub fn new(name: &'static str) -> Self {
        log::info!("Initialising subsystem manager {}", name);

        let (shutdown_request_tx, _shutdown_request_rx) = broadcast::channel(1);
        let (shutting_down_tx, shutting_down_rx) = mpsc::channel(1);

        Self {
            name,
            shutdown_request_tx,
            shutting_down_tx,
            shutting_down_rx,
        }
    }

    /// Build a new subsystem
    ///
    /// This gives more control over starting subsystems than [Manager::start] or
    /// [Manager::start_passive]. Use if extra parameter tuning is required.
    pub fn builder(&self) -> Builder<'_> {
        Builder::new(self)
    }

    /// Start a subsystem. See [Builder::start].
    pub fn start<T: 'static + Send, F: 'static + Send + Future<Output = ()>>(
        &self,
        name: &'static str,
        subsystem: impl 'static + Send + FnOnce(CallRequest<T>, ShutdownRequest) -> F,
    ) -> Subsystem<T> {
        self.builder().with_name(name).start(subsystem)
    }

    /// Start a passive subsystem. See [Builder::start_passive].
    pub fn start_passive<T: 'static + Send>(&self, name: &'static str, obj: T) -> Subsystem<T> {
        self.builder().with_name(name).start_passive(obj)
    }

    /// Install termination signal handlers.
    ///
    /// This adds a subsystem that listens for the Ctrl-C signal and exits once it is received,
    /// signalling all other subsystems and the whole manager to shut down.
    #[cfg(not(loom))]
    pub fn install_signal_handlers(&self) {
        self.start(
            "ctrl-c",
            |mut call_rq: CallRequest<()>, mut shutdown_rq| async move {
                tokio::select! {
                    ctrl_c_signal = tokio::signal::ctrl_c() => {
                        if ctrl_c_signal.is_err() {
                            log::info!("Ctrl-C signal handler failed");
                        }
                    }
                    () = shutdown_rq.recv() => {},
                    call = call_rq.recv() => { call(&mut ()); }
                };
            },
        );
    }

    /// Issue an asynchronous shutdown request
    pub async fn shutdown(&self) {
        self.shutting_down_tx.send(()).await.expect("Shutdown receiver not existing")
    }

    async fn wait_for_subsystems_to_shut_down(mut shutting_down_rx: mpsc::Receiver<()>) {
        // Wait for the subsystems to go down, signalled by closing the shutting_down channel.
        while let Some(()) = shutting_down_rx.recv().await {}
    }

    /// Run the application main task.
    ///
    /// Completes when all the subsystems are fully shut down.
    pub async fn main(mut self) {
        // The main task just waits for the shutdown signal and coordinates the cleanup at the end.
        // All other functionality is performed by subsystems.

        log::info!("Manager {} running", self.name);

        // Signal the manager is shut down so it does not wait for itself
        std::mem::drop(self.shutting_down_tx);

        // Wait for a subsystem to shut down.
        self.shutting_down_rx
            .recv()
            .await
            .unwrap_or_else(|| log::info!("Manager {}: all subsystems already down", self.name));

        log::info!("Manager {} shutting down", self.name);

        // Order all the remaining subsystems to shut down.
        let _ = self.shutdown_request_tx.send(());

        // Wait for the subsystems to go down.
        // TODO add shutdown timeout here
        Self::wait_for_subsystems_to_shut_down(self.shutting_down_rx).await;

        log::info!("Manager {} terminated", self.name);
    }
}

/// Subsystem builder
pub struct Builder<'a> {
    manager: &'a Manager,
    subsystem_name: &'static str,
    call_queue_capacity: usize,
}

impl<'a> Builder<'a> {
    const DEFAULT_CALL_QUEUE_CAPACITY: usize = 64;
    const DEFAULT_SUBSYSTEM_NAME: &'static str = "<unnamed>";

    fn new(manager: &'a Manager) -> Self {
        Self {
            manager,
            subsystem_name: Self::DEFAULT_SUBSYSTEM_NAME,
            call_queue_capacity: Self::DEFAULT_CALL_QUEUE_CAPACITY,
        }
    }

    /// Set call queue capacity
    pub fn with_call_queue_capacity(mut self, new_cap: usize) -> Self {
        self.call_queue_capacity = new_cap;
        self
    }

    /// Set subsystem name
    pub fn with_name(mut self, new_name: &'static str) -> Self {
        self.subsystem_name = new_name;
        self
    }

    /// Start the subsystem.
    ///
    /// A subsystem has to handle shutdown and call requests. It can also react to external IO
    /// events. If the subsystem handles *only* calls and shutdown requests without interaction
    /// with any additional IO, use the [Manager::start_passive] convenience method.
    ///
    /// A typical skeleton of a subsystem looks like this:
    /// ```no_run
    /// # let manager = subsystem::Manager::new("app");
    /// let subsystem = manager.start("my-subsystem", |mut call, mut shutdown| async move {
    ///     loop {
    ///         tokio::select! {
    ///             // Shutdown received, break out of the loop.
    ///             () = shutdown.recv() => { break; }
    ///             // Handle calls. An object representing the subsystem is passed in.
    ///             func = call.recv() => { func(todo!("put an argument here")); }
    ///             // Handle any other IO events here
    ///         };
    ///     }
    /// });
    /// # let _ = subsystem.call(|()| ());  // Fix the call type to avoid amnbiguity.
    /// ```
    pub fn start<T: 'static + Send, F: 'static + Send + Future<Output = ()>>(
        self,
        subsystem: impl 'static + Send + FnOnce(CallRequest<T>, ShutdownRequest) -> F,
    ) -> Subsystem<T> {
        // Name strings
        let manager_name = self.manager.name;
        let subsys_name = self.subsystem_name;
        // Shutdown-related channels
        let shutting_down_tx = self.manager.shutting_down_tx.clone();
        let shutdown_rq = ShutdownRequest(self.manager.shutdown_request_tx.subscribe());
        // Call related channels
        let (action_tx, action_rx) = mpsc::channel(self.call_queue_capacity);
        let call_rq = CallRequest(action_rx);

        task::spawn(async move {
            log::info!("Subsystem {}/{} started", manager_name, subsys_name);

            // Perform the subsystem task.
            subsystem(call_rq, shutdown_rq).await;

            // Signal the intent to shut down to the other parts of the application.
            shutting_down_tx.send(()).await.expect("Subsystem outlived the manager!?");

            log::info!("Subsystem {}/{} terminated", manager_name, subsys_name);

            // Close the channel to signal the completion of the shutdown.
            std::mem::drop(shutting_down_tx);
        });

        Subsystem::new(action_tx)
    }

    /// Start a passive subsystem.
    ///
    /// A passive subsystem does not interact with the environment on its own. It only serves calls
    /// from other subsystems.
    pub fn start_passive<T: 'static + Send>(self, mut obj: T) -> Subsystem<T> {
        self.start(|mut call_rq, mut shutdown_rq| async move {
            loop {
                tokio::select! {
                    () = shutdown_rq.recv() => { break; }
                    call = call_rq.recv() => { call(&mut obj).await; }
                }
            }
        })
    }
}

type FutureBox<'a, R> = core::pin::Pin<Box<dyn 'a + Send + Future<Output = R>>>;

// Internal action type sent in the channel.
type Action<T, R> = Box<dyn Send + for<'a> FnOnce(&'a mut T) -> FutureBox<'a, R>>;

/// Call request
pub struct CallRequest<T>(mpsc::Receiver<Action<T, ()>>);

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
pub struct ShutdownRequest(broadcast::Receiver<()>);

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
pub struct Subsystem<T> {
    // Send the subsystem stuff to do.
    action_tx: mpsc::Sender<Action<T, ()>>,
}

impl<T> Clone for Subsystem<T> {
    fn clone(&self) -> Self {
        Self {
            action_tx: self.action_tx.clone(),
        }
    }
}

impl<T: Send + 'static> Subsystem<T> {
    /// Crate a new subsystem handle.
    fn new(action_tx: mpsc::Sender<Action<T, ()>>) -> Self {
        Self { action_tx }
    }

    /// Dispatch an async function call to the subsystem
    pub async fn call_async_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> FutureBox<'a, R> + Send + 'static,
    ) -> R {
        let (rtx, rrx) = oneshot::channel::<R>();

        self.action_tx
            .send(Box::new(move |subsys| {
                Box::pin(async move {
                    let result = func(subsys).await;
                    rtx.send(result).ok().expect("Value return channel closed");
                })
            }))
            .await
            .ok()
            .expect("Target subsystem down upon call");

        rrx.await.expect("Target subsystem down upon result receive")
    }

    /// Dispatch an async function call to the subsystem (immutable)
    pub async fn call_async<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> FutureBox<'a, R> + Send + 'static,
    ) -> R {
        self.call_async_mut(|this| func(this)).await
    }

    /// Dispatch a function call to the subsystem
    pub async fn call_mut<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a mut T) -> R + Send + 'static,
    ) -> R {
        self.call_async_mut(|this| Box::pin(core::future::ready(func(this)))).await
    }

    /// Dispatch a function call to the subsystem (immutable)
    pub async fn call<R: Send + 'static>(
        &self,
        func: impl for<'a> FnOnce(&'a T) -> R + Send + 'static,
    ) -> R {
        self.call_mut(|this| func(this)).await
    }
}

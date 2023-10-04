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

//! Subsystem manager

mod manager_impl;
mod shutdown_signal;

pub use manager_impl::{Manager, ManagerJoinHandle, ShutdownTrigger};

use std::time::Duration;

/// Subsystem manager configuration options
pub struct ManagerConfig {
    /// Subsystem manager name
    pub name: &'static str,

    /// Shutdown timeout. Set to `None` for no (i.e. unlimited) timeout.
    pub shutdown_timeout_per_subsystem: Option<Duration>,

    /// Whether to enable signal handlers
    pub enable_signal_handlers: bool,
}

impl ManagerConfig {
    /// Default shutdown timeout.
    const DEFAULT_SHUTDOWN_TIMEOUT: Option<Duration> = if cfg!(all(feature = "time", not(loom))) {
        Some(Duration::from_secs(30))
    } else {
        None
    };

    /// New config using given subsystem name. Other options are default.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            shutdown_timeout_per_subsystem: Self::DEFAULT_SHUTDOWN_TIMEOUT,
            enable_signal_handlers: false,
        }
    }

    /// Full name of given subsystem.
    pub fn full_name_of(&self, subsys_name: &str) -> String {
        format!("{}/{}", self.name, subsys_name)
    }

    /// How long to wait for each subsystem before force-termination.
    #[cfg(all(feature = "time", not(loom)))]
    pub fn with_shutdown_timeout_per_subsystem(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout_per_subsystem = Some(timeout);
        self
    }

    /// Disable the timeout for subsystem shutdown.
    pub fn disable_shutdown_timeout(mut self) -> Self {
        self.shutdown_timeout_per_subsystem = None;
        self
    }

    /// Enable handling of `Ctrl-C` and other termination signals.
    #[cfg(not(loom))]
    pub fn enable_signal_handlers(mut self) -> Self {
        self.enable_signal_handlers = true;
        self
    }
}

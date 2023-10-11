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

//! Signals and channels for handling system shutdown.

/// Why is the system shutting down
#[derive(Debug)]
pub enum ShutdownReason {
    CtrlC,
    Term,
    Internal,
}

impl std::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ShutdownReason::CtrlC => "Ctrl-C signal received",
            ShutdownReason::Term => "Terminate signal received",
            ShutdownReason::Internal => "Shutdown initiated internally",
        })
    }
}

/// System is shutting down due to an error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Signal handler failed: {0}")]
    Signal(std::io::Error),
    #[error("All subsystems already down")]
    AllDown,
    #[error("Signal handler blocked")]
    Blocked,
}

/// External system shutdown trigger.
///
/// Listens for the Ctrl-C/termination signal and resolves once it is received.
#[cfg(not(loom))]
pub async fn external_shutdown() -> Result<ShutdownReason, Error> {
    // Gracefully handle SIGTERM on *nix
    #[cfg(unix)]
    let terminate = {
        use tokio::signal::unix;
        let mut sig = unix::signal(unix::SignalKind::terminate()).map_err(Error::Signal)?;
        async move { sig.recv().await }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<Option<()>>();

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map(|()| ShutdownReason::CtrlC).map_err(Error::Signal)
        }
        result = terminate => {
            result.map(|()| ShutdownReason::Term).ok_or(Error::Blocked)
        }
    }
}

#[cfg(loom)]
async fn external_shutdown() -> Result<ShutdownReason, Error> {
    std::future::pending()
}

/// System shutdown trigger
pub async fn shutdown_signal(
    mut shut: tokio::sync::mpsc::UnboundedReceiver<()>,
    enable_signal_handlers: bool,
) -> Result<ShutdownReason, Error> {
    tokio::select! {
        result = external_shutdown(), if enable_signal_handlers => {
            result
        }
        result = shut.recv() => {
            result.map(|()| ShutdownReason::Internal).ok_or(Error::AllDown)
        }
    }
}

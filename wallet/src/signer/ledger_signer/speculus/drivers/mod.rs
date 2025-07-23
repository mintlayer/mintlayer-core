// Copyright (c) 2025 RBB S.r.l
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

//! Podman driver for speculos execution, runs a speculos instance within
//! a Podman container.

use core::fmt::Debug;

use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command as TokioCommand,
    sync::oneshot::{channel, Sender},
};
use tracing::debug;

use crate::signer::ledger_signer::speculus::{Handle, Options};

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::Stdio,
};

/// [`Driver`] trait for speculos providers
#[async_trait]
pub trait Driver {
    type Handle: Debug;

    /// Run speculos with the specified app and options
    fn run(&self, app: &str, opts: Options) -> anyhow::Result<Self::Handle>;

    /// Exit task
    fn exit(&self, handle: Self::Handle) -> anyhow::Result<()>;
}

/// Podman-based Speculos driver
pub struct PodmanDriver;

/// Handle to a Speculos instance running under Podman
#[derive(Debug)]
pub struct PodmanHandle {
    name: String,
    addr: SocketAddr,
    // Sender to signal the log streaming task to shut down.
    exit_tx: Sender<()>,
}

impl PodmanDriver {
    /// Create a new podman driver.
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self)
    }

    /// Helper to run a synchronous std::process::Command in a non-blocking way.
    fn run_command(mut command: std::process::Command) -> anyhow::Result<std::process::Output> {
        let command_str = format!("{:?}", command);
        let output = command.output().unwrap();

        if !output.status.success() {
            anyhow::bail!(
                "Podman command failed: {}\nSTDOUT: {}\nSTDERR: {}",
                command_str,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        debug!(
            "Successfully ran podman command: {}\nSTDOUT: {}",
            command_str,
            String::from_utf8_lossy(&output.stdout)
        );
        Ok(output)
    }
}

const DEFAULT_IMAGE: &str = "ghcr.io/ledgerhq/speculos";

#[async_trait]
impl Driver for PodmanDriver {
    type Handle = PodmanHandle;

    fn run(&self, app: &str, opts: Options) -> anyhow::Result<Self::Handle> {
        let name = format!("speculos-{}", opts.http_port);

        // Ensure any previous container with the same name is removed.
        debug!("Force removing existing container '{}'", &name);
        let mut cleanup_cmd = std::process::Command::new("podman");
        cleanup_cmd.args(["rm", "-f", &name]);
        // We don't care if this fails (e.g., if the container didn't exist).
        let _ = Self::run_command(cleanup_cmd);

        // Path to the application binary and its parent directory.
        let app_path = PathBuf::from(app);
        let app_file_name = app_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid application path: {}", app))?;
        let app_parent_dir = app_path
            .parent()
            .and_then(|p| p.to_str())
            .ok_or_else(|| anyhow::anyhow!("Could not get parent directory of app: {}", app))?;

        // Setup the command to run inside the container.
        let mut speculos_cmd_args = opts.args();
        speculos_cmd_args.push(format!("/app/{}", app_file_name));

        debug!("Container command: {}", speculos_cmd_args.join(" "));

        // Build the `podman run` command.
        let mut command = std::process::Command::new("podman");
        command.arg("run");
        // command.args(["--detach", "--name", &name]);
        command.arg("--detach");
        command.arg("--name");
        command.arg(&name);

        command.arg("--log-driver=k8s-file");

        // Map ports.
        let mut ports = vec![opts.http_port];
        if let Some(p) = opts.apdu_port {
            ports.push(p);
        }
        for port in ports {
            command.arg("-p").arg(format!("{}:{}", port, port));
        }

        // Mount the app's directory as a volume instead of copying the file.
        // This is simpler and more efficient than creating a tarball.
        command.arg("-v").arg(format!("{}:/app:ro", app_parent_dir));

        // Set image and the command to run.
        command.arg(DEFAULT_IMAGE);
        command.args(&speculos_cmd_args);

        // Create and start the container.
        debug!("Creating and starting container '{}'", &name);
        Self::run_command(command)?;
        debug!("Container '{}' started", &name);

        let (exit_tx, mut exit_rx) = channel();

        // Spawn a task to stream container logs.
        let container_name_clone = name.clone();
        tokio::spawn(async move {
            debug!(
                "Starting log streaming for container '{}'",
                container_name_clone
            );
            let mut cmd = TokioCommand::new("podman");
            cmd.args(["logs", "--follow", &container_name_clone]);
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(child) => child,
                Err(e) => {
                    debug!("Failed to spawn podman logs: {}", e);
                    return;
                }
            };

            let stdout = child.stdout.take().expect("Failed to open stdout");
            let stderr = child.stderr.take().expect("Failed to open stderr");

            let mut stdout_reader = BufReader::new(stdout).lines();
            let mut stderr_reader = BufReader::new(stderr).lines();

            loop {
                tokio::select! {
                    // Check for exit signal
                    _ = &mut exit_rx => {
                        debug!("Received exit signal for log streaming. Killing process.");
                        let _ = child.kill().await;
                        break;
                    },
                    // Read from stdout
                    Ok(Some(line)) = stdout_reader.next_line() => {
                        println!("[{}] {}", container_name_clone, line);
                    },
                    // Read from stderr
                    Ok(Some(line)) = stderr_reader.next_line() => {
                        eprintln!("[{}] {}", container_name_clone, line);
                    },
                    // Break if log stream ends
                    else => break,
                }
            }
            debug!(
                "Log streaming task for '{}' finished.",
                container_name_clone
            );
        });

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), opts.http_port);
        Ok(PodmanHandle {
            name,
            addr,
            exit_tx,
        })
    }

    fn exit(&self, handle: Self::Handle) -> anyhow::Result<()> {
        debug!("Stopping container {}", handle.name);
        eprintln!("Stopping container {}", handle.name);

        // Signal the log streaming task to terminate.
        let _ = handle.exit_tx.send(());

        // Stop the container.
        let mut stop_cmd = std::process::Command::new("podman");
        stop_cmd.args(["stop", &handle.name]);
        // Ignore errors, as we will force remove it anyway.
        let _ = Self::run_command(stop_cmd);

        // Remove the container.
        debug!("Removing container {}", handle.name);
        let mut rm_cmd = std::process::Command::new("podman");
        rm_cmd.args(["rm", "-f", &handle.name]);
        Self::run_command(rm_cmd)?;

        debug!("Container {} removed", handle.name);
        Ok(())
    }
}

#[async_trait]
impl Handle for PodmanHandle {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

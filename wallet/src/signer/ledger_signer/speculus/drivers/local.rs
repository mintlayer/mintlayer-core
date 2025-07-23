//! Local driver for speculos execution, runs a speculos instance from the
//! local environment.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Stdio,
};

use async_trait::async_trait;
use tokio::process::{Child, Command};
use tracing::debug;

use crate::signer::ledger_signer::speculus::{Handle, Options};

use super::Driver;

/// Local (child process) based speculos driver
pub struct LocalDriver;

/// Handle to a speculos instance running locally (as a child process)
#[derive(Debug)]
pub struct LocalHandle {
    /// HTTP API socket address
    addr: SocketAddr,
    /// Child task handle
    child: Child,
}

impl LocalDriver {
    /// Create a new [LocalDriver]
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalDriver {
    /// Create a new [LocalDriver]
    fn default() -> Self {
        Self
    }
}

/// [Driver] implementation for [LocalDriver]
#[async_trait]
impl Driver for LocalDriver {
    type Handle = LocalHandle;

    async fn run(&self, app: &str, opts: Options) -> anyhow::Result<Self::Handle> {
        // Setup speculos command
        let mut cmd = Command::new("speculos.py");

        // Kill when object is dropped
        let mut cmd = cmd.kill_on_drop(true);

        // Bind stdout / stderr
        // NOTE: for reasons unknown test harnesses don't overwrite stdout so much as hack the `print!` family of functions, so... this always produces a pile of output
        // TODO: it'd be nice to route this via the captured log output were it one day possible to do so
        cmd = cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

        // Setup speculos arguments
        for a in opts.args() {
            cmd = cmd.arg(a);
        }

        if let Some(root) = opts.root {
            // Fetch existing path
            let (_, path) = std::env::vars()
                .find(|(k, _v)| k == "PATH")
                .unwrap_or(("PATH".to_string(), "".to_string()));

            cmd = cmd.env("PATH", format!("{path}:{root}"));
        }

        // Set application to execute
        cmd = cmd.arg(app);

        debug!("Command: {:?}", cmd);

        // Launch speculos and return
        let child = cmd.spawn()?;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), opts.http_port);
        Ok(LocalHandle { child, addr })
    }

    async fn wait_start(&self, handle: &mut Self::Handle) -> anyhow::Result<()> {
        let _status = handle.child.wait().await?;

        // TODO: match on status / return errors

        Ok(())
    }

    async fn wait(&self, handle: &mut Self::Handle) -> anyhow::Result<()> {
        let _status = handle.child.wait().await?;

        // TODO: match on status / return errors

        Ok(())
    }

    async fn exit(&self, mut handle: Self::Handle) -> anyhow::Result<()> {
        handle.child.kill().await?;
        Ok(())
    }
}

#[async_trait]
impl Handle for LocalHandle {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

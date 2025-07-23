//! Docker driver for speculos execution, runs a speculos instance within
//! a Docker container.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use async_trait::async_trait;
use bollard::{
    container::{
        Config, CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
        StopContainerOptions, UploadToContainerOptions,
    },
    service::{ContainerStateStatusEnum, HostConfig, PortBinding},
    Docker,
};
use bytes::{BufMut, BytesMut};
use futures::StreamExt;
use tokio::sync::oneshot::{channel, Sender};
use tracing::debug;

use super::Driver;
use crate::signer::ledger_signer::speculus::{Handle, Options};

/// Docker-based Speculos driver
pub struct DockerDriver {
    d: Docker,
}

/// Handle to a Speculos instance running under Docker
#[derive(Debug)]
pub struct DockerHandle {
    name: String,
    addr: SocketAddr,
    exit_tx: Sender<()>,
}

impl DockerDriver {
    /// Create a new docker driver
    pub fn new() -> Result<Self, anyhow::Error> {
        // Connect to docker instance
        let d = Docker::connect_with_local_defaults()?;

        // Return driver
        Ok(Self { d })
    }
}

const DEFAULT_IMAGE: &str = "ghcr.io/ledgerhq/speculos";

/// [Driver] implementation for [DockerDriver]
#[async_trait]
impl Driver for DockerDriver {
    type Handle = DockerHandle;

    async fn run(&self, app: &str, opts: Options) -> anyhow::Result<Self::Handle> {
        // Set container name
        let name = format!("speculos-{}", opts.http_port);
        let create_options = Some(CreateContainerOptions {
            name: &name,
            platform: None,
        });

        // Setup ports
        let mut ports = vec![opts.http_port];
        if let Some(p) = opts.apdu_port {
            ports.push(p);
        }

        let exposed_ports = ports.iter().map(|p| {
            // let b = PortBinding {
            //     host_port: Some(format!("{p}/tcp")),
            //     ..Default::default()
            // };
            let b = PortBinding {
                host_ip: Some("0.0.0.0".to_string()), // optional but recommended
                host_port: Some(format!("{}", p)),    // JUST the number!
                ..Default::default()
            };

            (format!("{p}/tcp"), vec![b], HashMap::<(), ()>::new())
        });

        let app_path = PathBuf::from(app);
        let app_file = app_path.file_name().and_then(|n| n.to_str()).unwrap();

        // Setup speculos command
        let mut cmd = vec![];
        cmd.append(&mut opts.args());
        cmd.push(format!("/app/{app_file}"));

        debug!("command: {}", cmd.join(" "));

        // Setup container
        let create_config = Config {
            image: Some(DEFAULT_IMAGE.to_string()),
            cmd: Some(cmd),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            stop_signal: Some("KILL".to_string()),
            exposed_ports: Some(HashMap::from_iter(
                exposed_ports.clone().map(|p| (p.0, p.2)),
            )),
            host_config: Some(HostConfig {
                port_bindings: Some(HashMap::from_iter(exposed_ports.map(|p| (p.0, Some(p.1))))),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Remove existing container if there is one
        let _ = self
            .d
            .remove_container(
                &name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;

        // Create container
        debug!("Creating container {}", name);
        let _create_info = self.d.create_container(create_options, create_config).await?;

        // Generate application archive
        let mut buff = BytesMut::new();
        let mut tar = tar::Builder::new((&mut buff).writer());

        tar.append_path_with_name(&app_path, format!("app/{app_file}"))?;

        tar.finish()?;
        drop(tar);

        // Write app archive to container
        let upload_options = UploadToContainerOptions {
            path: "/",
            ..Default::default()
        };
        self.d
            .upload_to_container(&name, Some(upload_options), buff.to_vec().into())
            .await?;

        // Start container
        debug!("Starting container {}", name);
        let _start_info =
            self.d.start_container(&name, None::<StartContainerOptions<String>>).await?;

        debug!("Container started");

        let (exit_tx, mut exit_rx) = channel();

        // Setup log streaming task
        let mut logs = self.d.logs::<String>(
            &name,
            Some(LogsOptions {
                stderr: true,
                stdout: true,
                follow: true,
                ..Default::default()
            }),
        );

        tokio::task::spawn(async move {
            debug!("start log task");

            loop {
                tokio::select! {
                    // Fetch log entries
                    l = logs.next() => {
                        match l {
                            Some(Ok(v)) => print!("{v}"),
                            Some(Err(e)) => {
                                debug!("exit log task: {:?}", e);
                                break;
                            },
                            _ => continue,
                        }
                    },
                    // Handle exit signal
                    _ = &mut exit_rx => {
                        break;
                    }
                }
            }
        });

        // Return container handle
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), opts.http_port);
        Ok(DockerHandle {
            name,
            addr,
            exit_tx,
        })
    }

    async fn wait_start(&self, handle: &mut Self::Handle) -> anyhow::Result<()> {
        use ContainerStateStatusEnum::*;

        debug!("Awaiting container completion");

        // Poll container info periodically
        loop {
            // Fetch container info
            let info = self.d.inspect_container(&handle.name, None).await?;

            debug!("info: {:?}", info);

            // Return when container exits
            match info.state.and_then(|s| s.status) {
                Some(CREATED) => (),
                Some(RUNNING) => return Ok(()),
                _ => (),
            }

            // Sleep for a while
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait(&self, handle: &mut Self::Handle) -> anyhow::Result<()> {
        use ContainerStateStatusEnum::*;

        debug!("Awaiting container completion");

        // Poll container info periodically
        loop {
            // Fetch container info
            let info = self.d.inspect_container(&handle.name, None).await?;

            debug!("info: {:?}", info);

            // Return when container exits
            match info.state.and_then(|s| s.status) {
                Some(CREATED) | Some(RUNNING) => (),
                Some(_) => return Ok(()),
                _ => (),
            }

            // Sleep for a while
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn exit(&self, handle: Self::Handle) -> anyhow::Result<()> {
        // Stop container
        debug!("Stopping container {}", handle.name);
        eprintln!("Stopping container {}", handle.name);

        // Send exit signal to log task
        let _ = handle.exit_tx.send(());

        // Send container stop signal
        let options = Some(StopContainerOptions { t: 0 });
        let _ = self.d.stop_container(&handle.name, options).await;

        // Remove container
        debug!("Removing container");
        let options = Some(RemoveContainerOptions {
            force: true,
            ..Default::default()
        });
        self.d.remove_container(&handle.name, options).await?;

        debug!("Container removed");

        Ok(())
    }
}

#[async_trait]
impl Handle for DockerHandle {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Node initialisation routine.

use std::{fs, sync::Arc};

use anyhow::{Context, Result};

use chainstate::rpc::ChainstateRpcServer;
use common::chain::config::ChainType;
use logging::log;
use p2p::rpc::P2pRpcServer;

use crate::{
    config::NodeConfig,
    options::{Command, Options},
};

#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
enum Error {
    #[error("Chain type '{0}' not yet supported")]
    UnsupportedChain(ChainType),
}

/// Initialize the node, giving caller the opportunity to add more subsystems before start.
pub async fn initialize(
    chain_type: ChainType,
    node_config: NodeConfig,
) -> Result<subsystem::Manager> {
    // Initialize storage.
    let storage = chainstate_storage::Store::new_empty()?;

    // Initialize chain configuration.
    let chain_config = Arc::new(match chain_type {
        ChainType::Mainnet => common::chain::config::create_mainnet(),
        ChainType::Regtest => common::chain::config::create_regtest(),
        chain_ty => return Err(Error::UnsupportedChain(chain_ty).into()),
    });

    // INITIALIZE SUBSYSTEMS

    let mut manager = subsystem::Manager::new("mintlayer");
    manager.install_signal_handlers();

    // Chainstate subsystem
    let chainstate = manager.add_subsystem(
        "chainstate",
        chainstate::make_chainstate(
            Arc::clone(&chain_config),
            node_config.chainstate,
            storage.clone(),
            None,
            Default::default(),
        )?,
    );

    // P2P subsystem
    let p2p = manager.add_subsystem(
        "p2p",
        p2p::make_p2p::<p2p::net::libp2p::Libp2pService>(
            Arc::clone(&chain_config),
            node_config.p2p,
            chainstate.clone(),
        )
        .await
        .expect("The p2p subsystem initialization failed"),
    );

    // RPC subsystem
    let _rpc = manager.add_subsystem(
        "rpc",
        rpc::Builder::new(node_config.rpc)
            .register(chainstate.clone().into_rpc())
            .register(NodeRpc::new(manager.make_shutdown_trigger()).into_rpc())
            .register(p2p.clone().into_rpc())
            .build()
            .await?,
    );

    Ok(manager)
}

/// Processes options and potentially runs the node.
pub async fn run(options: Options) -> Result<()> {
    match options.command {
        Command::CreateConfig => {
            let path = options.config_path();
            let config = NodeConfig::new(options.data_dir)?;
            let config = toml::to_string(&config).context("Failed to serialize config")?;
            log::trace!("Saving config to {path:?}\n: {config:#?}");
            fs::write(&path, config)
                .with_context(|| format!("Failed to write config to the '{path:?}' file"))?;
            Ok(())
        }
        Command::Run(ref run_options) => {
            let node_config = NodeConfig::read(&options.config_path(), run_options)
                .context("Failed to initialize config")?;
            log::trace!("Starting with the following config\n: {node_config:#?}");
            let manager = initialize(run_options.net, node_config).await?;
            manager.main().await;
            Ok(())
        }
    }
}

#[rpc::rpc(server, namespace = "node")]
trait NodeRpc {
    /// Order the node to shutdown
    #[method(name = "shutdown")]
    fn shutdown(&self) -> rpc::Result<()>;

    /// Get node software version
    #[method(name = "version")]
    fn version(&self) -> rpc::Result<String>;
}

struct NodeRpc {
    shutdown_trigger: subsystem::manager::ShutdownTrigger,
}

impl NodeRpc {
    fn new(shutdown_trigger: subsystem::manager::ShutdownTrigger) -> Self {
        Self { shutdown_trigger }
    }
}

impl NodeRpcServer for NodeRpc {
    fn shutdown(&self) -> rpc::Result<()> {
        self.shutdown_trigger.initiate();
        Ok(())
    }

    fn version(&self) -> rpc::Result<String> {
        Ok(env!("CARGO_PKG_VERSION").into())
    }
}

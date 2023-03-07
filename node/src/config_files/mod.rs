// Copyright (c) 2022 RBB S.r.l
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

//! The node configuration.

pub use self::{chainstate_launcher::StorageBackendConfigFile, p2p::NodeTypeConfigFile};

mod chainstate;
mod chainstate_launcher;
mod p2p;
mod rpc;

use std::{fs, net::SocketAddr, path::Path, str::FromStr};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::RunOptions;

use self::{
    chainstate::ChainstateConfigFile, chainstate_launcher::ChainstateLauncherConfigFile,
    p2p::P2pConfigFile, rpc::RpcConfigFile,
};

/// The node configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeConfigFile {
    // Subsystems configurations.
    pub chainstate: Option<ChainstateLauncherConfigFile>,
    pub p2p: Option<P2pConfigFile>,
    pub rpc: Option<RpcConfigFile>,
}

impl NodeConfigFile {
    pub fn new() -> Result<Self> {
        Ok(Self {
            chainstate: None,
            p2p: None,
            rpc: None,
        })
    }

    fn read_to_string_with_policy<P: AsRef<Path>>(config_path: P) -> Result<String> {
        let config_as_str = if config_path.as_ref().exists() {
            fs::read_to_string(config_path.as_ref()).context(format!(
                "Unable to read config file in {}",
                config_path.as_ref().display()
            ))?
        } else {
            "".into()
        };
        Ok(config_as_str)
    }

    /// Reads a configuration from the specified path and overrides the provided parameters.
    pub fn read(config_path: &Path, options: &RunOptions) -> Result<Self> {
        let config_as_str = Self::read_to_string_with_policy(config_path)?;

        let NodeConfigFile {
            chainstate,
            p2p,
            rpc,
        } = toml::from_str(&config_as_str).context("Failed to parse config")?;

        let chainstate = chainstate_config(chainstate.unwrap_or_default(), options);
        let p2p = p2p_config(p2p.unwrap_or_default(), options);
        let rpc = rpc_config(rpc.unwrap_or_default(), options);

        Ok(Self {
            chainstate: Some(chainstate),
            p2p: Some(p2p),
            rpc: Some(rpc),
        })
    }
}

fn chainstate_config(
    config: ChainstateLauncherConfigFile,
    options: &RunOptions,
) -> ChainstateLauncherConfigFile {
    let ChainstateLauncherConfigFile {
        storage_backend,
        chainstate_config,
    } = config;

    let ChainstateConfigFile {
        max_db_commit_attempts,
        max_orphan_blocks,
        min_max_bootstrap_import_buffer_sizes,
        tx_index_enabled,
        max_tip_age,
    } = chainstate_config;

    let storage_backend = options.storage_backend.clone().unwrap_or(storage_backend);
    let max_db_commit_attempts = options.max_db_commit_attempts.or(max_db_commit_attempts);
    let max_orphan_blocks = options.max_orphan_blocks.or(max_orphan_blocks);
    let tx_index_enabled = options.tx_index_enabled.or(tx_index_enabled);
    let max_tip_age = options.max_tip_age.or(max_tip_age);

    let chainstate_config = ChainstateConfigFile {
        max_db_commit_attempts,
        max_orphan_blocks,
        min_max_bootstrap_import_buffer_sizes,
        tx_index_enabled,
        max_tip_age,
    };
    ChainstateLauncherConfigFile {
        storage_backend,
        chainstate_config,
    }
}

fn p2p_config(config: P2pConfigFile, options: &RunOptions) -> P2pConfigFile {
    let P2pConfigFile {
        bind_addresses,
        boot_nodes,
        reserved_nodes,
        max_inbound_connections,
        ban_threshold,
        ban_duration,
        outbound_connection_timeout,
        ping_check_period,
        ping_timeout,
        node_type,
    } = config;

    let bind_addresses = options.p2p_addr.clone().or(bind_addresses);
    let boot_nodes = options.p2p_boot_node.clone().or(boot_nodes);
    let reserved_nodes = options.p2p_reserved_node.clone().or(reserved_nodes);
    let max_inbound_connections = options.p2p_max_inbound_connections.or(max_inbound_connections);
    let ban_threshold = options.p2p_ban_threshold.or(ban_threshold);
    let ping_check_period = options.p2p_ping_check_period.or(ping_check_period);
    let ping_timeout = options.p2p_ping_timeout.or(ping_timeout);
    let outbound_connection_timeout =
        options.p2p_outbound_connection_timeout.or(outbound_connection_timeout);
    let node_type = options.node_type.or(node_type);

    P2pConfigFile {
        bind_addresses,
        boot_nodes,
        reserved_nodes,
        max_inbound_connections,
        ban_threshold,
        ban_duration,
        outbound_connection_timeout,
        ping_check_period,
        ping_timeout,
        node_type,
    }
}

fn rpc_config(config: RpcConfigFile, options: &RunOptions) -> RpcConfigFile {
    const DEFAULT_HTTP_RPC_ENABLED: bool = true;
    // TODO: Disabled by default because it causes port bind issues in functional tests; to be fixed after #446 is resolved
    const DEFAULT_WS_RPC_ENABLED: bool = false;
    let default_http_rpc_addr = SocketAddr::from_str("127.0.0.1:3030").expect("Can't fail");
    let default_ws_rpc_addr = SocketAddr::from_str("127.0.0.1:3032").expect("Can't fail");

    let RpcConfigFile {
        http_bind_address,
        http_enabled,
        ws_bind_address,
        ws_enabled,
    } = config;

    let http_bind_address = options
        .http_rpc_addr
        .unwrap_or_else(|| http_bind_address.unwrap_or(default_http_rpc_addr));
    let http_enabled = options
        .http_rpc_enabled
        .unwrap_or_else(|| http_enabled.unwrap_or(DEFAULT_HTTP_RPC_ENABLED));
    let ws_bind_address = options
        .ws_rpc_addr
        .unwrap_or_else(|| ws_bind_address.unwrap_or(default_ws_rpc_addr));
    let ws_enabled = options
        .ws_rpc_enabled
        .unwrap_or_else(|| ws_enabled.unwrap_or(DEFAULT_WS_RPC_ENABLED));

    RpcConfigFile {
        http_bind_address: Some(http_bind_address),
        http_enabled: Some(http_enabled),
        ws_bind_address: Some(ws_bind_address),
        ws_enabled: Some(ws_enabled),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crypto::random::{distributions::Alphanumeric, make_pseudo_rng, Rng};

    use super::*;

    #[test]
    fn no_values_required_in_toml_files() {
        let _config: NodeConfigFile = toml::from_str("").unwrap();
        let _config: chainstate_launcher::ChainstateLauncherConfigFile =
            toml::from_str("").unwrap();
        let _config: chainstate::ChainstateConfigFile = toml::from_str("").unwrap();
        let _config: p2p::P2pConfigFile = toml::from_str("").unwrap();
        let _config: rpc::RpcConfigFile = toml::from_str("").unwrap();
    }

    #[test]
    fn read_config_file_nonexistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let config_file_data = NodeConfigFile::read_to_string_with_policy(config_path).unwrap();
        assert_eq!(config_file_data, "");
    }

    #[test]
    fn read_config_file_exists_with_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let injected_config_data = make_pseudo_rng()
            .sample_iter(&Alphanumeric)
            .take(1024)
            .map(char::from)
            .collect::<String>();

        {
            let mut file = fs::File::create(config_path.clone()).unwrap();
            file.write_all(injected_config_data.as_bytes()).unwrap();
        }
        let read_config_data = NodeConfigFile::read_to_string_with_policy(config_path).unwrap();
        assert_eq!(read_config_data, injected_config_data);
    }

    #[test]
    fn read_config_file_path_exists_but_is_not_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");

        fs::create_dir(config_path.clone()).unwrap();

        let _err = NodeConfigFile::read_to_string_with_policy(config_path).unwrap_err();
    }
}

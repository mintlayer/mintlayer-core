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

pub const DEFAULT_RPC_ENABLED: bool = true;
pub const DEFAULT_P2P_NETWORKING_ENABLED: bool = true;

pub use self::{
    chainstate_launcher::StorageBackendConfigFile, p2p::NodeTypeConfigFile, rpc::RpcConfigFile,
};

mod blockprod;
mod chainstate;
mod chainstate_launcher;
mod mempool;
mod p2p;
mod rpc;

use std::{fs, path::Path};

use ::chainstate_launcher::ChainConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::RunOptions;

use self::{
    blockprod::BlockProdConfigFile, chainstate::ChainstateConfigFile,
    chainstate_launcher::ChainstateLauncherConfigFile, mempool::MempoolConfigFile,
    p2p::P2pConfigFile,
};

/// The node configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NodeConfigFile {
    // Subsystems configurations.
    pub blockprod: Option<BlockProdConfigFile>,
    pub chainstate: Option<ChainstateLauncherConfigFile>,
    pub mempool: Option<MempoolConfigFile>,
    pub p2p: Option<P2pConfigFile>,
    pub rpc: Option<RpcConfigFile>,
}

impl NodeConfigFile {
    pub fn new() -> Result<Self> {
        Ok(Self {
            blockprod: None,
            chainstate: None,
            mempool: None,
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
    pub fn read(
        chain_config: &ChainConfig,
        config_path: &Path,
        options: &RunOptions,
    ) -> Result<Self> {
        let config_as_str = Self::read_to_string_with_policy(config_path)?;

        let NodeConfigFile {
            blockprod,
            chainstate,
            mempool,
            p2p,
            rpc,
        } = toml::from_str(&config_as_str).context("Failed to parse config")?;

        let blockprod = blockprod_config(blockprod.unwrap_or_default(), options);
        let chainstate = chainstate_config(chainstate.unwrap_or_default(), options);
        let mempool = MempoolConfigFile::with_run_options(mempool.unwrap_or_default(), options);
        let p2p = p2p_config(p2p.unwrap_or_default(), options);
        let rpc = RpcConfigFile::with_run_options(chain_config, rpc.unwrap_or_default(), options);

        Ok(Self {
            blockprod: Some(blockprod),
            chainstate: Some(chainstate),
            mempool: Some(mempool),
            p2p: Some(p2p),
            rpc: Some(rpc),
        })
    }
}

fn blockprod_config(config: BlockProdConfigFile, options: &RunOptions) -> BlockProdConfigFile {
    const DEFAULT_MIN_PEERS_TO_PRODUCE_BLOCKS: usize = 3;

    let BlockProdConfigFile {
        min_peers_to_produce_blocks,
        skip_ibd_check,
        use_current_time_if_non_pos,
    } = config;

    let min_peers_to_produce_blocks = options
        .blockprod_min_peers_to_produce_blocks
        .or(min_peers_to_produce_blocks.or(Some(DEFAULT_MIN_PEERS_TO_PRODUCE_BLOCKS)));

    let skip_ibd_check = options.blockprod_skip_ibd_check.or(skip_ibd_check).unwrap_or(false);
    let use_current_time_if_non_pos = options
        .blockprod_use_current_time_if_non_pos
        .or(use_current_time_if_non_pos)
        .unwrap_or(false);

    BlockProdConfigFile {
        min_peers_to_produce_blocks,
        skip_ibd_check: Some(skip_ibd_check),
        use_current_time_if_non_pos: Some(use_current_time_if_non_pos),
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
        max_tip_age,
        enable_heavy_checks,
        allow_checkpoints_mismatch,
    } = chainstate_config;

    let storage_backend = options.storage_backend.clone().unwrap_or(storage_backend);
    let max_db_commit_attempts = options.max_db_commit_attempts.or(max_db_commit_attempts);
    let max_orphan_blocks = options.max_orphan_blocks.or(max_orphan_blocks);
    let max_tip_age = options.max_tip_age.or(max_tip_age);
    let enable_heavy_checks = options.enable_chainstate_heavy_checks.or(enable_heavy_checks);
    let allow_checkpoints_mismatch =
        options.allow_checkpoints_mismatch.or(allow_checkpoints_mismatch);

    let chainstate_config = ChainstateConfigFile {
        max_db_commit_attempts,
        max_orphan_blocks,
        min_max_bootstrap_import_buffer_sizes,
        max_tip_age,
        enable_heavy_checks,
        allow_checkpoints_mismatch,
    };
    ChainstateLauncherConfigFile {
        storage_backend,
        chainstate_config,
    }
}

fn p2p_config(config: P2pConfigFile, options: &RunOptions) -> P2pConfigFile {
    let P2pConfigFile {
        networking_enabled,
        bind_addresses,
        socks5_proxy,
        disable_noise,
        boot_nodes,
        reserved_nodes,
        whitelisted_addresses,
        max_inbound_connections,
        discouragement_threshold,
        discouragement_duration,
        max_clock_diff,
        outbound_connection_timeout,
        ping_check_period,
        ping_timeout,
        sync_stalling_timeout,
        node_type,
        force_dns_query_if_no_global_addresses_known,
    } = config;

    let networking_enabled = options.p2p_networking_enabled.or(networking_enabled);
    let bind_addresses = options.p2p_bind_addresses.clone().or(bind_addresses);
    let socks5_proxy = options.p2p_socks5_proxy.clone().or(socks5_proxy);
    let disable_noise = options.p2p_disable_noise.or(disable_noise);
    let boot_nodes = options.p2p_boot_nodes.clone().or(boot_nodes);
    let reserved_nodes = options.p2p_reserved_nodes.clone().or(reserved_nodes);
    let whitelisted_addresses = options.p2p_whitelist_addr.clone().or(whitelisted_addresses);
    let max_inbound_connections = options.p2p_max_inbound_connections.or(max_inbound_connections);
    let discouragement_threshold =
        options.p2p_discouragement_threshold.or(discouragement_threshold);
    let discouragement_duration = options.p2p_discouragement_duration.or(discouragement_duration);
    let ping_check_period = options.p2p_ping_check_period.or(ping_check_period);
    let ping_timeout = options.p2p_ping_timeout.or(ping_timeout);
    let max_clock_diff = options.p2p_max_clock_diff.or(max_clock_diff);
    let outbound_connection_timeout =
        options.p2p_outbound_connection_timeout.or(outbound_connection_timeout);
    let sync_stalling_timeout = options.p2p_sync_stalling_timeout.or(sync_stalling_timeout);
    let node_type = options.node_type.or(node_type);
    let force_dns_query_if_no_global_addresses_known = options
        .p2p_force_dns_query_if_no_global_addresses_known
        .or(force_dns_query_if_no_global_addresses_known);

    P2pConfigFile {
        networking_enabled,
        bind_addresses,
        socks5_proxy,
        disable_noise,
        boot_nodes,
        reserved_nodes,
        whitelisted_addresses,
        max_inbound_connections,
        discouragement_threshold,
        discouragement_duration,
        max_clock_diff,
        outbound_connection_timeout,
        ping_check_period,
        ping_timeout,
        sync_stalling_timeout,
        node_type,
        force_dns_query_if_no_global_addresses_known,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use randomness::{distributions::Alphanumeric, make_pseudo_rng, Rng};

    use super::*;

    #[test]
    fn no_values_required_in_toml_files() {
        let _config: NodeConfigFile = toml::from_str("").unwrap();
        let _config: BlockProdConfigFile = toml::from_str("").unwrap();
        let _config: ChainstateLauncherConfigFile = toml::from_str("").unwrap();
        let _config: ChainstateConfigFile = toml::from_str("").unwrap();
        let _config: P2pConfigFile = toml::from_str("").unwrap();
        let _config: RpcConfigFile = toml::from_str("").unwrap();
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

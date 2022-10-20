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

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use chainstate::ChainstateConfig;
use p2p::config::{MdnsConfig, P2pConfig};
use rpc::RpcConfig;

use crate::RunOptions;

/// The node configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeConfig {
    /// The path to the data directory.
    ///
    /// By default the config file is created inside of the data directory.
    pub datadir: PathBuf,

    // Subsystems configurations.
    pub chainstate: ChainstateConfig,
    pub p2p: P2pConfig,
    pub rpc: RpcConfig,
}

impl NodeConfig {
    /// Creates a new `Config` instance with the given data directory path.
    pub fn new(datadir: PathBuf) -> Result<Self> {
        let chainstate = ChainstateConfig::new();
        let p2p = P2pConfig::new();
        let rpc = RpcConfig::new()?;
        Ok(Self {
            datadir,
            chainstate,
            p2p,
            rpc,
        })
    }

    /// Reads a configuration from the specified path and overrides the provided parameters.
    pub fn read(config_path: &Path, options: &RunOptions) -> Result<Self> {
        let config = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read '{config_path:?}' config"))?;
        let NodeConfig {
            datadir,
            chainstate,
            p2p,
            rpc,
        } = toml::from_str(&config).context("Failed to parse config")?;

        let chainstate = chainstate_config(chainstate, options);
        let p2p = p2p_config(p2p, options);
        let rpc = rpc_config(rpc, options);

        Ok(Self {
            datadir,
            chainstate,
            p2p,
            rpc,
        })
    }
}

fn chainstate_config(config: ChainstateConfig, options: &RunOptions) -> ChainstateConfig {
    let ChainstateConfig {
        max_db_commit_attempts,
        max_orphan_blocks,
        min_max_bootstrap_import_buffer_sizes,
    } = config;

    let max_db_commit_attempts = options.max_db_commit_attempts.unwrap_or(max_db_commit_attempts);
    let max_orphan_blocks = options.max_orphan_blocks.unwrap_or(max_orphan_blocks);

    ChainstateConfig {
        max_db_commit_attempts,
        max_orphan_blocks,
        min_max_bootstrap_import_buffer_sizes,
    }
}

fn p2p_config(config: P2pConfig, options: &RunOptions) -> P2pConfig {
    let P2pConfig {
        bind_address,
        ban_threshold,
        outbound_connection_timeout,
        mdns_config: _,
    } = config;

    let bind_address = options.p2p_addr.clone().unwrap_or(bind_address);
    let ban_threshold = options.p2p_ban_threshold.unwrap_or(ban_threshold);
    let outbound_connection_timeout =
        options.p2p_outbound_connection_timeout.unwrap_or(outbound_connection_timeout);

    P2pConfig {
        bind_address,
        ban_threshold,
        outbound_connection_timeout,
        mdns_config: MdnsConfig::from_options(
            options.p2p_enable_mdns.unwrap_or(false),
            options.p2p_mdns_query_interval,
            options.p2p_enable_ipv6_mdns_discovery,
        ),
    }
}

fn rpc_config(config: RpcConfig, options: &RunOptions) -> RpcConfig {
    let default_http_rpc_addr = SocketAddr::from_str("127.0.0.1:3030").expect("Can't fail");
    const DEFAULT_HTTP_RPC_ENABLED: bool = true;
    let default_ws_rpc_addr = SocketAddr::from_str("127.0.0.1:3031").expect("Can't fail");
    // TODO: Disabled by default because it causes port bind issues in functional tests
    const DEFAULT_WS_RPC_ENABLED: bool = false;

    let RpcConfig {
        http_bind_address,
        http_enabled,
        ws_bind_address,
        ws_enabled,
    } = config;

    let http_bind_address = options
        .http_rpc_addr
        .unwrap_or(http_bind_address.unwrap_or(default_http_rpc_addr));
    let http_enabled = options
        .http_rpc_enabled
        .unwrap_or(http_enabled.unwrap_or(DEFAULT_HTTP_RPC_ENABLED));
    let ws_bind_address =
        options.ws_rpc_addr.unwrap_or(ws_bind_address.unwrap_or(default_ws_rpc_addr));
    let ws_enabled = options.ws_rpc_enabled.unwrap_or(ws_enabled.unwrap_or(DEFAULT_WS_RPC_ENABLED));

    RpcConfig {
        http_bind_address: Some(http_bind_address),
        http_enabled: Some(http_enabled),
        ws_bind_address: Some(ws_bind_address),
        ws_enabled: Some(ws_enabled),
    }
}

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

//! The node configuration.

use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use chainstate::ChainstateConfig;
use p2p::config::P2pConfig;
use rpc::RpcConfig;

use crate::RunOptions;

/// The node configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeConfig {
    // Subsystems configurations.
    pub chainstate: ChainstateConfig,
    pub p2p: P2pConfig,
    pub rpc: RpcConfig,
}

impl NodeConfig {
    /// Creates a new `Config` instance for the specified chain type.
    pub fn new() -> Result<Self> {
        let chainstate = ChainstateConfig::new();
        let p2p = P2pConfig::new();
        let rpc = RpcConfig::new()?;
        Ok(Self {
            chainstate,
            p2p,
            rpc,
        })
    }

    /// Reads a configuration from the path specified in options and overrides the provided
    /// parameters.
    pub fn read(options: &RunOptions) -> Result<Self> {
        let config = fs::read_to_string(&options.config_path)
            .with_context(|| format!("Failed to read '{:?}' config", options.config_path))?;
        let NodeConfig {
            chainstate,
            p2p,
            rpc,
        } = toml::from_str(&config).context("Failed to deserialize config")?;

        let chainstate = chainstate_config(chainstate, options);
        let p2p = p2p_config(p2p, options);
        let rpc = rpc_config(rpc, options);

        Ok(Self {
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
    } = config;

    let max_db_commit_attempts = options.max_db_commit_attempts.unwrap_or(max_db_commit_attempts);
    let max_orphan_blocks = options.max_orphan_blocks.unwrap_or(max_orphan_blocks);

    ChainstateConfig {
        max_db_commit_attempts,
        max_orphan_blocks,
    }
}

fn p2p_config(config: P2pConfig, options: &RunOptions) -> P2pConfig {
    let P2pConfig {
        bind_address,
        ban_threshold,
        outbound_connection_timeout,
    } = config;

    let bind_address = options.p2p_addr.clone().unwrap_or(bind_address);
    let ban_threshold = options.p2p_ban_threshold.unwrap_or(ban_threshold);
    let outbound_connection_timeout =
        options.p2p_outbound_connection_timeout.unwrap_or(outbound_connection_timeout);

    P2pConfig {
        bind_address,
        ban_threshold,
        outbound_connection_timeout,
    }
}

fn rpc_config(config: RpcConfig, options: &RunOptions) -> RpcConfig {
    let RpcConfig { address } = config;

    let address = options.rpc_addr.unwrap_or(address);

    RpcConfig { address }
}

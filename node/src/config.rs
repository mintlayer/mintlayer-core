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
use common::chain::config::ChainType;
use p2p::config::P2pConfig;
use rpc::RpcConfig;

use crate::RunOptions;

/// The node configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub chain_type: ChainType,

    // Subsystems configurations.
    pub chainstate: ChainstateConfig,
    pub p2p: P2pConfig,
    pub rpc: RpcConfig,
}

impl Config {
    /// Creates a new `Config` instance for the specified chain type.
    pub fn new(chain_type: ChainType) -> Result<Self> {
        let chainstate = chainstate::Config::new();
        let p2p = p2p::Config::new();
        let rpc = rpc::Config::new()?;
        Ok(Self {
            chain_type,
            chainstate,
            p2p,
            rpc,
        })
    }

    /// Reads a configuration from the path specified in options and overrides the provided
    /// parameters.
    pub fn read(options: RunOptions) -> Result<Self> {
        let config = fs::read_to_string(&options.config_path).context("Failed to read config")?;
        let mut config: Config = toml::from_str(&config).context("Failed to deserialize config")?;

        // Chainstate options.
        if let Some(max_size) = options.max_block_header_size {
            config.chainstate.max_block_header_size = max_size;
        }
        if let Some(max_size) = options.max_block_size_from_txs {
            config.chainstate.max_block_size_from_txs = max_size;
        }
        if let Some(max_size) = options.max_block_size_from_smart_contracts {
            config.chainstate.max_block_size_from_smart_contracts = max_size;
        }

        // P2p options.
        if let Some(address) = options.p2p_addr {
            config.p2p.address = address;
        }

        // Rpc options.
        if let Some(address) = options.rpc_addr {
            config.rpc.address = address;
        }

        Ok(config)
    }
}

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

//! The node command line options.

use std::{ffi::OsString, net::SocketAddr, num::NonZeroU64, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use common::chain::config::ChainType;
use utils::default_data_dir::default_data_dir_common;

use crate::{
    config_files::{NodeTypeConfigFile, StorageBackendConfigFile},
    regtest_options::RegtestOptions,
};

const CONFIG_NAME: &str = "config.toml";

/// Mintlayer node executable
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Options {
    /// The path to the data directory.
    #[clap(short, long = "datadir")]
    pub data_dir: Option<PathBuf>,

    #[clap(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Run the mainnet node.
    Mainnet(RunOptions),
    /// Run the testnet node.
    Testnet(RunOptions),
    /// Run the regtest node.
    Regtest(RegtestOptions),
}

#[derive(Args, Clone, Debug, Default)]
pub struct RunOptions {
    /// Storage backend to use.
    #[clap(long)]
    pub storage_backend: Option<StorageBackendConfigFile>,

    /// A node type.
    #[clap(long)]
    pub node_type: Option<NodeTypeConfigFile>,

    /// Mock time used to initialize the node time at startup, in seconds (valid only for regtest).
    #[clap(long)]
    #[arg(hide = true)]
    pub mock_time: Option<u64>,

    /// The number of maximum attempts to process a block.
    #[clap(long)]
    pub max_db_commit_attempts: Option<usize>,

    /// The maximum capacity of the orphan blocks pool in blocks.
    #[clap(long)]
    pub max_orphan_blocks: Option<usize>,

    /// Maintain a full transaction index.
    #[clap(long)]
    pub tx_index_enabled: Option<bool>,

    /// Address to bind P2P to.
    #[clap(long, value_name = "ADDR")]
    pub p2p_addr: Option<Vec<String>>,

    /// Connect through SOCKS5 proxy.
    #[clap(long)]
    pub p2p_socks5_proxy: Option<String>,

    /// Disable p2p encryption (for tests only).
    #[clap(long)]
    #[arg(hide = true)]
    pub p2p_disable_noise: Option<bool>,

    /// Optional list of boot node addresses to connect.
    #[clap(long, value_name = "NODE")]
    pub p2p_boot_node: Option<Vec<String>>,

    /// Optional list of reserved node addresses to connect.
    #[clap(long, value_name = "NODE")]
    pub p2p_reserved_node: Option<Vec<String>>,

    /// Maximum allowed number of inbound connections.
    #[clap(long)]
    pub p2p_max_inbound_connections: Option<usize>,

    /// The p2p score threshold after which a peer is baned.
    #[clap(long)]
    pub p2p_ban_threshold: Option<u32>,

    /// The p2p timeout value in seconds.
    #[clap(long)]
    pub p2p_outbound_connection_timeout: Option<NonZeroU64>,

    /// How often send ping requests to peers (in seconds).
    /// Set to 0 to disable sending ping requests.
    #[clap(long)]
    pub p2p_ping_check_period: Option<u64>,

    /// After what time a peer is detected as dead and is disconnected (in seconds).
    #[clap(long)]
    pub p2p_ping_timeout: Option<NonZeroU64>,

    /// A maximum tip age in seconds.
    ///
    /// The initial block download is finished if the difference between the current time and the
    /// tip time is less than this value.
    #[clap(long)]
    pub max_tip_age: Option<u64>,

    /// Address to bind http RPC to.
    #[clap(long, value_name = "ADDR")]
    pub http_rpc_addr: Option<SocketAddr>,

    /// Enable/Disable http RPC.
    #[clap(long)]
    pub http_rpc_enabled: Option<bool>,

    /// Address to bind websocket RPC to.
    #[clap(long, value_name = "ADDR")]
    pub ws_rpc_addr: Option<SocketAddr>,

    /// Enable/Disable websocket RPC.
    #[clap(long)]
    pub ws_rpc_enabled: Option<bool>,

    /// Username for RPC HTTP and WebSocket server basic authorization.
    /// If not set, the cookie file is created.
    #[clap(long)]
    pub rpc_username: Option<String>,

    /// Password for RPC HTTP and WebSocket server basic authorization.
    /// If not set, the RPC cookie file is created.
    #[clap(long)]
    pub rpc_password: Option<String>,

    /// Custom file path for the RPC cookie file.
    /// If not set, the cookie file is created in the data dir.
    #[clap(long)]
    pub rpc_cookie_file: Option<String>,
}

impl Options {
    /// Constructs an instance by parsing the given arguments.
    ///
    /// The data directory is created as a side-effect of the invocation.
    /// Process is terminated on error.
    pub fn from_args<A: Into<OsString> + Clone>(args: impl IntoIterator<Item = A>) -> Self {
        Parser::parse_from(args)
    }

    /// Returns the data directory
    pub fn data_dir(&self) -> &Option<PathBuf> {
        &self.data_dir
    }

    /// Returns a path to the config file
    pub fn config_path(&self, chain_type: ChainType) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| default_data_dir(chain_type))
            .join(CONFIG_NAME)
    }
}

pub fn default_data_dir(chain_type: ChainType) -> PathBuf {
    default_data_dir_common().join(chain_type.name())
}

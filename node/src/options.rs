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

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use directories::UserDirs;

use crate::{
    config_files::{NodeTypeConfigFile, StorageBackendConfigFile},
    regtest_options::RegtestOptions,
};

const DATA_DIR_NAME: &str = ".mintlayer";
const CONFIG_NAME: &str = "config.toml";

/// Mintlayer node executable
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Options {
    /// The path to the data directory.
    #[clap(short, long = "datadir")]
    pub data_dir: Option<PathBuf>,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the mainnet node.
    Mainnet(RunOptions),
    /// Run the testnet node.
    Testnet(RunOptions),
    /// Run the regtest node.
    Regtest(RegtestOptions),
}

#[derive(Args, Debug, Default)]
pub struct RunOptions {
    /// Storage backend to use.
    #[clap(long)]
    pub storage_backend: Option<StorageBackendConfigFile>,

    /// A node type.
    #[clap(long)]
    pub node_type: Option<NodeTypeConfigFile>,

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

    /// Optional list of initial node addresses to connect.
    #[clap(long, value_name = "NODE")]
    pub p2p_add_node: Option<Vec<String>>,

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
    pub p2p_ping_timeout: Option<u64>,

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
}

impl Options {
    /// Constructs an instance by parsing the given arguments.
    ///
    /// The data directory is created as a side-effect of the invocation.
    pub fn from_args<A: Into<OsString> + Clone>(args: impl IntoIterator<Item = A>) -> Result<Self> {
        let options: Options = clap::Parser::try_parse_from(args)?;

        Ok(options)
    }

    /// Returns the data directory
    pub fn data_dir(&self) -> &Option<PathBuf> {
        &self.data_dir
    }

    /// Returns a path to the config file
    pub fn config_path(&self) -> PathBuf {
        self.data_dir.clone().unwrap_or_else(default_data_dir).join(CONFIG_NAME)
    }
}

pub fn default_data_dir() -> PathBuf {
    UserDirs::new()
        // Expect here is OK because `Parser::parse_from` panics anyway in case of error.
        .expect("Unable to get home directory")
        .home_dir()
        .join(DATA_DIR_NAME)
}

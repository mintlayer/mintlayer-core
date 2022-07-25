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

//! The node command line options.

use std::{ffi::OsString, fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use directories::UserDirs;

const DATA_DIR_NAME: &str = ".mintlayer";
const CONFIG_NAME: &str = "config.toml";

/// Mintlayer node executable
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Options {
    /// Where to write logs
    #[clap(long, value_name = "PATH")]
    pub log_path: Option<PathBuf>,

    /// The path to the data directory.
    #[clap(short, long = "datadir", default_value_os_t = default_data_dir())]
    pub data_dir: PathBuf,

    /// The path to the config file.
    #[clap(short, long = "conf")]
    config_path: Option<PathBuf>,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a configuration file.
    CreateConfig,
    Mainnet(RunOptions),
    Regtest(RegtestOptions),
}

/// Run the mainnet node.
#[derive(Args, Debug)]
pub struct RunOptions {
    /// The number of maximum attempts to process a block.
    #[clap(long)]
    pub max_db_commit_attempts: Option<usize>,

    /// The maximum capacity of the orphan blocks pool in blocks.
    #[clap(long)]
    pub max_orphan_blocks: Option<usize>,

    /// Address to bind P2P to.
    #[clap(long, value_name = "ADDR")]
    pub p2p_addr: Option<String>,

    /// The p2p score threshold after which a peer is baned.
    #[clap(long)]
    pub p2p_ban_threshold: Option<u32>,

    /// The p2p timeout value in seconds.
    #[clap(long)]
    pub p2p_outbound_connection_timeout: Option<u64>,

    /// Address to bind RPC to.
    #[clap(long, value_name = "ADDR")]
    pub rpc_addr: Option<SocketAddr>,
}

/// Run the regtest node.
#[derive(Args, Debug)]
pub struct RegtestOptions {
    #[clap(flatten)]
    pub run_options: RunOptions,
    #[clap(flatten)]
    pub chain_config: ChainConfigOptions,
}

#[derive(Args, Debug)]
pub struct ChainConfigOptions {
    /// Address prefix.
    #[clap(long)]
    pub chain_address_prefix: Option<String>,

    /// Block reward maturity.
    #[clap(long)]
    pub chain_blockreward_maturity: Option<i64>,

    /// The maximum future block offset in seconds.
    #[clap(long)]
    pub chain_max_future_block_time_offset: Option<u64>,

    /// The chain version (major.minor.path).
    #[clap(long)]
    pub chain_version: Option<String>,

    /// Target block spacing in seconds.
    #[clap(long)]
    pub chain_target_block_spacing: Option<u64>,

    /// Coin decimals.
    #[clap(long)]
    pub chain_coin_decimals: Option<u8>,

    /// The maximum block header size in bytes.
    #[clap(long)]
    pub chain_max_block_header_size: Option<usize>,

    /// The maximum transactions size in block in bytes.
    #[clap(long)]
    pub chain_max_block_size_with_standard_txs: Option<usize>,

    /// The maximum smart contracts size ib block in bytes.
    #[clap(long)]
    pub chain_max_block_size_with_smart_contracts: Option<usize>,
}

impl Options {
    /// Constructs an instance by parsing the given arguments.
    ///
    /// The data directory is created as a side-effect of the invocation.
    pub fn from_args<A: Into<OsString> + Clone>(args: impl IntoIterator<Item = A>) -> Result<Self> {
        let options: Options = clap::Parser::parse_from(args);

        // We want to check earlier if directories can be created.
        fs::create_dir_all(&options.data_dir).with_context(|| {
            format!(
                "Failed to create the '{:?}' data directory",
                options.data_dir
            )
        })?;
        // Config can potentially be stored in location different from the data directory.
        if let Some(config_dir) = options.config_path.as_ref().and_then(|p| p.parent()) {
            fs::create_dir_all(config_dir).with_context(|| {
                format!("Failed to create the '{config_dir:?}' config directory")
            })?;
        }

        Ok(options)
    }

    /// Returns a path to the config file.
    pub fn config_path(&self) -> PathBuf {
        self.config_path.clone().unwrap_or_else(|| self.data_dir.join(CONFIG_NAME))
    }
}

fn default_data_dir() -> PathBuf {
    UserDirs::new()
        // Expect here is OK because `Parser::parse_from` panics anyway in case of error.
        .expect("Unable to get home directory")
        .home_dir()
        .join(DATA_DIR_NAME)
}

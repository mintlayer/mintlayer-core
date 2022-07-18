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

use std::{ffi::OsString, net::SocketAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use strum::VariantNames;

use common::chain::config::ChainType;

/// Mintlayer node executable
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Options {
    /// Where to write logs
    #[clap(long, value_name = "PATH")]
    pub log_path: Option<PathBuf>,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a configuration file.
    CreateConfig {
        /// The path where config will be created.
        // TODO: Use a system-specific location by default such as `%APPDATA%` on Windows and
        // `~/Library/Application Support` on Mac.
        #[clap(short, long, default_value = "./.mintlayer/mintlayer.toml")]
        path: PathBuf,
    },
    Run(RunOptions),
}

#[derive(Args, Debug)]
pub struct RunOptions {
    /// The path to the configuration file.
    // TODO: Use a system-specific location by default such as `%APPDATA%` on Windows and
    // `~/Library/Application Support` on Mac.
    #[clap(short, long, default_value = "./.mintlayer/mintlayer.toml")]
    pub config_path: PathBuf,

    /// Blockchain type.
    #[clap(long, possible_values = ChainType::VARIANTS, default_value = "mainnet")]
    pub net: ChainType,

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

impl Options {
    pub fn from_args<A: Into<OsString> + Clone>(args: impl IntoIterator<Item = A>) -> Self {
        clap::Parser::parse_from(args)
    }
}

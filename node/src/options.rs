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

use std::{ffi::OsString, net::SocketAddr, path::PathBuf, time::Duration};

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
    Run(RunOptions),
    /// Create a configuration file.
    CreateConfig {
        /// The path where config will be created.
        #[clap(short, long, default_value = "./mintlayer.toml")]
        path: PathBuf,
        /// Blockchain type.
        #[clap(long, possible_values = ChainType::VARIANTS, default_value = "mainnet")]
        net: ChainType,
    },
}

#[derive(Args, Debug)]
pub struct RunOptions {
    /// The path to the configuration file.
    #[clap(short, long, default_value = "./mintlayer.toml")]
    pub config_path: PathBuf,
    /// Target block spacing.
    #[clap(long)]
    pub target_block_spacing: Option<Duration>,
    /// Maximum header size.
    #[clap(long)]
    pub max_block_header_size: Option<usize>,
    /// Maximum transactions size in a block.
    #[clap(long)]
    pub max_block_size_from_txs: Option<usize>,
    /// Maximum smart contracts size in a block.
    #[clap(long)]
    pub max_block_size_from_smart_contracts: usize,
    /// Address to bind P2P to.
    #[clap(long, value_name = "ADDR")]
    pub p2p_addr: Option<String>,
    /// Address to bind RPC to.
    #[clap(long, value_name = "ADDR")]
    pub rpc_addr: Option<SocketAddr>,
}

impl Options {
    pub fn from_args<A: Into<OsString> + Clone>(args: impl IntoIterator<Item = A>) -> Self {
        clap::Parser::parse_from(args)
    }
}

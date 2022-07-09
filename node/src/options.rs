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

use std::{ffi::OsString, path::PathBuf};

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

    /// Blockchain type
    #[clap(long, possible_values = ChainType::VARIANTS, default_value = "mainnet")]
    pub net: ChainType,

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
    #[clap(long, value_name = "ADDR")]
    pub p2p_addr: Option<String>,
}

impl Options {
    pub fn from_args<A: Into<OsString> + Clone>(args: impl IntoIterator<Item = A>) -> Self {
        clap::Parser::parse_from(args)
    }
}

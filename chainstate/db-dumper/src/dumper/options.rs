// Copyright (c) 2021-2025 RBB S.r.l
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

use std::path::PathBuf;

use clap::FromArgMatches as _;
use itertools::Itertools as _;
use strum::IntoEnumIterator as _;

use common::chain::config::ChainType;

use chainstate_db_dumper_lib::{
    BlockOutputField, DEFAULT_BLOCK_OUTPUT_FIELDS_MAINCHAIN_ONLY,
    DEFAULT_BLOCK_OUTPUT_FIELDS_WITH_STALE_CHAINS,
};

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum ChainTypeOption {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl ChainTypeOption {
    pub fn chain_type(&self) -> ChainType {
        match self {
            ChainTypeOption::Mainnet => ChainType::Mainnet,
            ChainTypeOption::Testnet => ChainType::Testnet,
            ChainTypeOption::Regtest => ChainType::Regtest,
            ChainTypeOption::Signet => ChainType::Signet,
        }
    }
}

const MAINCHAIN_ONLY_OPT_NAME: &str = "mainchain-only";

/// Dump block information from the chainstate db into a CSV file
#[derive(clap::Parser, Debug, Clone)]
pub struct Options {
    /// Chain type
    #[clap(short, long = "chain-type")]
    pub chain_type: ChainTypeOption,

    /// The path to the chainstate-lmdb directory.
    ///
    /// The default value is the default location corresponding to the specified chain type.
    #[clap(short, long = "db-dir")]
    pub db_dir: Option<PathBuf>,

    /// Output file
    #[clap(short, long = "output-file")]
    pub output_file: PathBuf,

    /// Whether to only dump mainchain blocks
    #[clap(long = MAINCHAIN_ONLY_OPT_NAME, action = clap::ArgAction::Set, default_value_t = true)]
    pub mainchain_only: bool,

    /// Block height to start from
    #[clap(long = "from_height", default_value_t = 0)]
    pub from_height: u64,

    /// This help string
    #[clap(long = "fields")]
    pub fields: Option<String>,
}

impl Options {
    /// Build the command adding custom description to "fields".
    pub fn build() -> clap::Command {
        let default_fields_mc_only = default_fields(true).iter().join(",");
        let default_fields_all_blocks = default_fields(false).iter().join(",");
        let all_fields = BlockOutputField::iter().join(", ");

        let fields_help = format!(
            concat!(
                "Comma-separated list of fields to dump.\n",
                "The default value depends on --{}, if true: '{}', if false: '{}'\n",
                "All possible fields are: {}"
            ),
            MAINCHAIN_ONLY_OPT_NAME, default_fields_mc_only, default_fields_all_blocks, all_fields
        );

        let cmd = <Self as clap::CommandFactory>::command();
        cmd.mut_arg("fields", |arg| arg.help(fields_help))
    }

    /// Custom `parse` function that used `build` defined above.
    pub fn parse() -> Self {
        let matches = Self::build().get_matches();

        match Self::from_arg_matches(&matches) {
            Ok(this) => this,
            Err(err) => err.exit(),
        }
    }
}

pub fn default_fields(mainchain_only: bool) -> &'static [BlockOutputField] {
    if mainchain_only {
        &DEFAULT_BLOCK_OUTPUT_FIELDS_MAINCHAIN_ONLY
    } else {
        &DEFAULT_BLOCK_OUTPUT_FIELDS_WITH_STALE_CHAINS
    }
}

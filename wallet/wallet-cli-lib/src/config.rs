// Copyright (c) 2023 RBB S.r.l
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

use clap::{Args, Parser, Subcommand};
use common::chain::config::{regtest_options::ChainConfigOptions, ChainType};

#[derive(Subcommand, Clone, Debug)]
pub enum Network {
    Mainnet(CliArgs),
    Testnet(CliArgs),
    Regtest(Box<RegtestOptions>),
    Signet(CliArgs),
}

#[derive(Args, Clone, Debug)]
pub struct RegtestOptions {
    #[clap(flatten)]
    pub run_options: CliArgs,
    #[clap(flatten)]
    pub chain_config: ChainConfigOptions,
}

#[derive(Parser, Debug)]
#[clap(version)]
#[command(args_conflicts_with_subcommands = true)]
pub struct WalletCliArgs {
    /// Network
    #[clap(subcommand)]
    pub network: Option<Network>,

    #[clap(flatten)]
    pub run_options: CliArgs,
}

impl WalletCliArgs {
    pub fn cli_args(self) -> CliArgs {
        self.network.map_or(self.run_options, |network| match network {
            Network::Mainnet(args) | Network::Signet(args) | Network::Testnet(args) => args,
            Network::Regtest(args) => args.run_options,
        })
    }
}

#[derive(Args, Clone, Debug)]
pub struct CliArgs {
    /// Optional path to the wallet file
    #[clap(long)]
    pub wallet_file: Option<PathBuf>,

    /// Optional password for a locked wallet
    #[clap(long)]
    pub wallet_password: Option<String>,

    /// Start staking after the start
    #[clap(long)]
    pub start_staking: bool,

    /// Optional RPC address
    #[clap(long)]
    pub rpc_address: Option<String>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub rpc_cookie_file: Option<String>,

    /// RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_username: Option<String>,

    /// RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_password: Option<String>,

    /// Run commands from the file
    #[clap(long)]
    pub commands_file: Option<PathBuf>,

    /// Preserve history file between application runs.
    /// This can be very insecure, use at your own risk!
    #[clap(long)]
    pub history_file: Option<PathBuf>,

    /// Exit on error. The default is true in non-interactive mode and false in interactive mode.
    #[clap(long)]
    pub exit_on_error: Option<bool>,

    /// vi input mode
    #[clap(long)]
    pub vi_mode: bool,

    /// In which top N MB should we aim for our transactions to be in the mempool
    /// e.g. for 5, we aim to be in the top 5 MB of transactions based on paid fees
    /// This is to avoid getting trimmed off the lower end if the mempool runs out of memory
    #[arg(long, default_value_t = 5)]
    pub in_top_x_mb: usize,
}

impl From<&Network> for ChainType {
    fn from(value: &Network) -> Self {
        match value {
            Network::Mainnet(_) => ChainType::Mainnet,
            Network::Testnet(_) => ChainType::Testnet,
            Network::Regtest(_) => ChainType::Regtest,
            Network::Signet(_) => ChainType::Signet,
        }
    }
}

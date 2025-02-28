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
use crypto::key::hdkd::u31::U31;
use utils::clap_utils;
use utils_networking::NetworkAddressWithPort;
use wallet_rpc_lib::cmdline::CliHardwareWalletType;

#[derive(Subcommand, Clone, Debug)]
pub enum Network {
    #[clap(mut_args(clap_utils::env_adder("MAINNET_WALLET")))]
    Mainnet(CliArgs),
    #[clap(mut_args(clap_utils::env_adder("TESTNET_WALLET")))]
    Testnet(CliArgs),
    #[clap(mut_args(clap_utils::env_adder("REGTEST_WALLET")))]
    Regtest(Box<RegtestOptions>),
    #[clap(mut_args(clap_utils::env_adder("SIGNET_WALLET")))]
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
#[clap(mut_args(clap_utils::env_adder("WALLET")))]
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
#[command(
    group(
        clap::ArgGroup::new("remote_rpc_auth")
            .args(["remote_rpc_wallet_cookie_file", "remote_rpc_wallet_username", "remote_rpc_wallet_no_authentication"])
            .required(false),
    ),
)]
pub struct CliArgs {
    /// Optional path to the wallet file
    #[clap(long)]
    pub wallet_file: Option<PathBuf>,

    /// Optional password for a locked wallet
    #[clap(long)]
    pub wallet_password: Option<String>,

    /// Force change the wallet type from hot to cold or from cold to hot
    #[clap(long, requires("wallet_file"))]
    pub force_change_wallet_type: bool,

    /// Specified if the wallet file is of a hardware wallet type e.g. Trezor
    #[arg(long, requires("wallet_file"))]
    pub hardware_wallet: Option<CliHardwareWalletType>,

    /// DEPRECATED: use start_staking_for_account instead!
    /// Start staking for the DEFAULT account after starting the wallet
    #[clap(long, requires("wallet_file"))]
    pub start_staking: bool,

    /// Start staking for the specified account after starting the wallet
    #[clap(long, requires("wallet_file"), value_delimiter(','))]
    pub start_staking_for_account: Vec<U31>,

    /// Optional RPC address
    #[clap(long)]
    pub node_rpc_address: Option<NetworkAddressWithPort>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub node_rpc_cookie_file: Option<String>,

    /// RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub node_rpc_username: Option<String>,

    /// RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub node_rpc_password: Option<String>,

    /// Run commands from the file
    #[clap(long)]
    pub commands_file: Option<PathBuf>,

    /// Preserve history file between application runs.
    /// This can be very insecure as it also stores things like the seed-phrase, use at your own risk!
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

    /// use the wallet without a connection to a node
    #[arg(long, conflicts_with_all(["node_rpc_address", "node_rpc_cookie_file", "node_rpc_username", "node_rpc_password"]))]
    pub cold_wallet: bool,

    /// enable the RPC interface of the wallet (i.e., run a wallet RPC server with the CLI)
    #[clap(long)]
    pub enable_wallet_rpc_interface: bool,

    /// Address to bind the RPC server to (assuming wallet RPC server is enabled)
    #[arg(long, value_name("ADDR"))]
    pub wallet_rpc_bind_address: Option<String>,

    /// Path to the wallet RPC cookie file (assuming wallet RPC server is enabled). If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub wallet_rpc_cookie_file: Option<PathBuf>,

    /// RPC username (assuming wallet RPC server is enabled) (either provide a username and password, or use a cookie file, or disable auth)
    #[clap(long)]
    pub wallet_rpc_username: Option<String>,

    /// RPC password (assuming wallet RPC server is enabled) (either provide a username and password, or use a cookie file, or disable auth)
    #[clap(long)]
    pub wallet_rpc_password: Option<String>,

    /// Enable running the wallet service without RPC authentication (assuming wallet RPC server is enabled)
    #[arg(long, conflicts_with_all(["wallet_rpc_password", "wallet_rpc_username", "wallet_rpc_cookie_file"]))]
    pub wallet_rpc_no_authentication: bool,

    /// Optionally, the wallet CLI can only be an interface to another remote wallet, accessible through RPC.
    /// So, you can start an RPC daemon, and make this CLI connect to it to control it.
    /// This is useful for servers, where the RPC wallet can be left staking,
    /// and the wallet CLI is used to control its state.
    #[arg(long, requires("remote_rpc_auth"), conflicts_with_all(["wallet_file", "wallet_rpc_password", "wallet_rpc_username", "wallet_rpc_cookie_file", "wallet_rpc_no_authentication", "wallet_rpc_bind_address", "node_rpc_address", "node_rpc_cookie_file", "node_rpc_username", "node_rpc_password"]))]
    pub remote_rpc_wallet_address: Option<String>,

    /// For a remote RPC wallet, this is the path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub remote_rpc_wallet_cookie_file: Option<String>,

    /// For a remote RPC wallet, this is the RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[arg(long, conflicts_with_all(["remote_rpc_wallet_cookie_file"]))]
    pub remote_rpc_wallet_username: Option<String>,

    /// For a remote RPC wallet, this is the RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[arg(long, conflicts_with_all(["remote_rpc_wallet_cookie_file"]), requires("remote_rpc_wallet_username"))]
    pub remote_rpc_wallet_password: Option<String>,

    /// For a remote RPC wallet, this will not use any authentication
    #[arg(long, conflicts_with_all(["remote_rpc_wallet_password", "remote_rpc_wallet_username", "remote_rpc_wallet_cookie_file"]))]
    pub remote_rpc_wallet_no_authentication: bool,

    /// Disable QR code output for wallet commands
    #[arg(long)]
    pub no_qr: bool,
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

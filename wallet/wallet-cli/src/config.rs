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

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use clap::Parser;
use common::chain::config::ChainType;

use crate::WalletCliError;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

#[derive(Parser, Debug)]
pub struct WalletCliArgs {
    /// Network
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// Optional path to the wallet file
    #[clap(long)]
    pub wallet_file: Option<PathBuf>,

    /// Optional RPC address
    #[clap(long)]
    pub rpc_address: Option<SocketAddr>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub rpc_cookie_file: Option<String>,

    /// RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_username: Option<String>,

    /// RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_password: Option<String>,

    /// vi input mode
    #[clap(long)]
    pub vi_mode: bool,
}

pub const COOKIE_FILENAME: &str = ".cookie";

impl From<Network> for ChainType {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Regtest => ChainType::Regtest,
            Network::Signet => ChainType::Signet,
        }
    }
}

pub fn load_cookie(path: impl AsRef<Path>) -> Result<(String, String), WalletCliError> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| WalletCliError::CookieFileReadError(path.as_ref().to_owned(), e))?;
    let (username, password) = content.split_once(':').ok_or(WalletCliError::InvalidConfig(
        format!("Invalid cookie file {:?}: ':' not found", path.as_ref()),
    ))?;
    Ok((username.to_owned(), password.to_owned()))
}

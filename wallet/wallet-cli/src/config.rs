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
    str::FromStr,
};

use clap::Parser;
use common::chain::config::ChainType;
use utils::default_data_dir::{default_data_dir_for_chain, prepare_data_dir};

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

    /// Optional path to the directory containing the wallet files
    #[clap(long)]
    pub wallets_dir: Option<PathBuf>,

    /// Optional wallet file name
    #[clap(long)]
    pub wallet_name: Option<PathBuf>,

    /// Optional RPC address
    #[clap(long)]
    pub rpc_address: Option<SocketAddr>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub rpc_cookie_file: Option<String>,

    /// RPC username
    #[clap(long)]
    pub rpc_username: Option<String>,

    /// RPC password
    #[clap(long)]
    pub rpc_password: Option<String>,

    /// vi input mode
    #[clap(long)]
    pub vi_mode: bool,
}

#[derive(Debug)]
pub struct WalletCliConfig {
    pub chain_type: ChainType,
    pub data_dir: PathBuf,
    pub wallet_file: PathBuf,
    pub rpc_address: SocketAddr,
    pub rpc_username: String,
    pub rpc_password: String,
    pub vi_mode: bool,
}

const DEFAULT_WALLETS_DIR: &str = "wallets";
const DEFAULT_WALLET_NAME: &str = "wallet";

const COOKIE_FILENAME: &str = ".cookie";

fn load_cookie(path: impl AsRef<Path>) -> Result<(String, String), WalletCliError> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| WalletCliError::CookieFileReadError(path.as_ref().to_owned(), e))?;
    let (username, password) = content.split_once(':').ok_or(WalletCliError::InvalidConfig(
        format!("Invalid cookie file {:?}: ':' not found", path.as_ref()),
    ))?;
    Ok((username.to_owned(), password.to_owned()))
}

impl WalletCliConfig {
    pub fn from_args(args: WalletCliArgs) -> Result<WalletCliConfig, WalletCliError> {
        let WalletCliArgs {
            network,
            wallets_dir,
            wallet_name,
            rpc_address,
            rpc_cookie_file,
            rpc_username,
            rpc_password,
            vi_mode,
        } = args;

        let chain_type = match network {
            Network::Mainnet => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Regtest => ChainType::Regtest,
            Network::Signet => ChainType::Signet,
        };

        let data_dir = prepare_data_dir(
            || default_data_dir_for_chain(chain_type.name()).join(DEFAULT_WALLETS_DIR),
            &wallets_dir,
        )
        .map_err(WalletCliError::PrepareData)?;
        let wallet_file = data_dir.join(wallet_name.unwrap_or(DEFAULT_WALLET_NAME.into()));

        // TODO: Use the constant with the node
        let default_http_rpc_addr = || SocketAddr::from_str("127.0.0.1:3030").expect("Can't fail");
        let rpc_address = rpc_address.unwrap_or_else(default_http_rpc_addr);

        let (rpc_username, rpc_password) = match (rpc_cookie_file, rpc_username, rpc_password) {
            (None, None, None) => {
                load_cookie(default_data_dir_for_chain(chain_type.name()).join(COOKIE_FILENAME))?
            }
            (Some(cookie_path), None, None) => load_cookie(cookie_path)?,
            (None, Some(username), Some(password)) => (username, password),
            _ => {
                return Err(WalletCliError::InvalidConfig(
                    "Invalid RPC cookie/username/password combination".to_owned(),
                ))
            }
        };

        Ok(WalletCliConfig {
            chain_type,
            data_dir,
            wallet_file,
            rpc_address,
            rpc_username,
            rpc_password,
            vi_mode,
        })
    }
}

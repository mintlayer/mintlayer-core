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

// Use `cli_println` instead
#![deny(clippy::print_stdout)]

mod commands;
mod config;
mod console;
mod errors;
mod helpers;
mod repl;
mod wallet_init;

use std::{net::SocketAddr, str::FromStr, sync::Arc};

use clap::Parser;
use common::chain::config::ChainType;
use config::WalletCliArgs;
use console::ConsoleContext;
use dialoguer::theme::ColorfulTheme;
use errors::WalletCliError;
use utils::default_data_dir::{default_data_dir_for_chain, prepare_data_dir};
use wallet::Wallet;
use wallet_controller::cookie::load_cookie;

const COOKIE_FILENAME: &str = ".cookie";

async fn run(output: &ConsoleContext) -> Result<(), WalletCliError> {
    logging::init_logging::<&std::path::Path>(None);

    let args = config::WalletCliArgs::parse();

    let WalletCliArgs {
        network,
        wallet_file,
        rpc_address,
        rpc_cookie_file,
        rpc_username,
        rpc_password,
        vi_mode,
    } = args;

    let chain_type: ChainType = network.into();
    let chain_config = Arc::new(common::chain::config::Builder::new(chain_type).build());
    let theme = ColorfulTheme::default();
    // TODO: Support other languages
    let language = wallet::wallet::Language::English;

    // TODO: Use the constant with the node
    let default_http_rpc_addr = || SocketAddr::from_str("127.0.0.1:3030").expect("Can't fail");
    let rpc_address = rpc_address.unwrap_or_else(default_http_rpc_addr);

    let (rpc_username, rpc_password) = match (rpc_cookie_file, rpc_username, rpc_password) {
        (None, None, None) => {
            let cookie_file_path =
                default_data_dir_for_chain(chain_type.name()).join(COOKIE_FILENAME);
            load_cookie(cookie_file_path.clone())
                .map_err(|e| WalletCliError::CookieFileReadError(cookie_file_path, e))?
        }
        (Some(cookie_file_path), None, None) => load_cookie(&cookie_file_path)
            .map_err(|e| WalletCliError::CookieFileReadError(cookie_file_path.into(), e))?,
        (None, Some(username), Some(password)) => (username, password),
        _ => {
            return Err(WalletCliError::InvalidConfig(
                "Invalid RPC cookie/username/password combination".to_owned(),
            ))
        }
    };

    let data_dir = prepare_data_dir(|| default_data_dir_for_chain(chain_type.name()), &None)
        .map_err(WalletCliError::PrepareData)?;

    let wallet_path = match wallet_file {
        Some(path) => path,
        None => wallet_init::input_wallet_path(&theme)?.into(),
    };
    let file_exists = wallet_path
        .try_exists()
        .map_err(|e| WalletCliError::FileIoError(wallet_path.clone(), e))?;

    let wallet = if file_exists {
        let db = wallet::wallet::open_or_create_wallet_file(&wallet_path)
            .map_err(WalletCliError::WalletError)?;

        Wallet::load_wallet(Arc::clone(&chain_config), db).map_err(WalletCliError::WalletError)?
    } else {
        // Try to get new mnemonic before creating wallet file, it should not be created if user cancels prompt!
        let mnemonic = wallet_init::input_new_wallet_mnemonic(language, output, &theme)?;
        let db = wallet::wallet::open_or_create_wallet_file(&wallet_path)
            .map_err(WalletCliError::WalletError)?;
        // TODO: Add optional passphrase

        Wallet::new_wallet(Arc::clone(&chain_config), db, &mnemonic.to_string(), None)
            .map_err(WalletCliError::WalletError)?
    };

    let controller = wallet_controller::make_rpc_controller(
        rpc_address,
        Some((&rpc_username, &rpc_password)),
        wallet,
    )
    .await
    .map_err(WalletCliError::Controller)?;

    repl::start_cli_repl(output, controller, &data_dir, vi_mode).await
}

#[tokio::main]
async fn main() {
    let output = ConsoleContext::new();
    run(&output).await.unwrap_or_else(|err| match err {
        WalletCliError::Cancelled | WalletCliError::Exit => {}
        e => {
            cli_println!(&output, "wallet-cli launch failed: {e}");
            std::process::exit(1)
        }
    })
}

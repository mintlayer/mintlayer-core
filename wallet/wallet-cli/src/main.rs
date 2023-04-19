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

use std::sync::Arc;

use clap::Parser;
use dialoguer::theme::ColorfulTheme;
use errors::WalletCliError;
use node_comm::make_rpc_client;
use wallet::{Wallet, WalletError};

mod commands;
mod config;
mod errors;
mod helpers;
mod repl;
mod wallet_init;

// TODO(PR): Add a context
#[macro_export]
macro_rules! cli_println {
    ($($arg:tt)*) => { ::std::println!($($arg)*) };
}

type DefWallet = Wallet<wallet_storage::DefaultBackend>;

async fn run() -> Result<(), WalletCliError> {
    logging::init_logging::<&std::path::Path>(None);

    let args = config::WalletCliArgs::parse();
    let config = config::WalletCliConfig::from_args(args)?;
    let chain_config = Arc::new(common::chain::config::Builder::new(config.chain_type).build());

    let db = wallet::wallet::open_or_create_wallet_file(&config.wallet_file)
        .map_err(WalletCliError::WalletError)?;

    let theme = ColorfulTheme::default();

    let wallet = match Wallet::load_wallet(Arc::clone(&chain_config), Arc::clone(&db)) {
        Ok(wallet) => wallet,
        Err(WalletError::WalletNotInitialized) => {
            wallet_init::new_wallet(chain_config, db, &theme)?
        }
        Err(e) => return Err(WalletCliError::WalletError(e)),
    };

    let rpc_client = make_rpc_client(
        config.rpc_address,
        Some((&config.rpc_username, &config.rpc_password)),
    )
    .await
    .map_err(|e| WalletCliError::RpcError(e.to_string()))?;

    repl::start_cli_repl(&config, rpc_client, wallet).await
}

#[tokio::main]
async fn main() {
    run().await.unwrap_or_else(|err| {
        cli_println!("wallet-cli launch failed: {err}");
        std::process::exit(1)
    })
}

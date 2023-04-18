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

use std::{collections::VecDeque, path::PathBuf, sync::Arc};

use clap::Parser;
use common::chain::ChainConfig;
use dialoguer::{theme::ColorfulTheme, History};
use node_comm::{make_rpc_client, node_traits::NodeInterface};
use utils::default_data_dir::PrepareDataDirError;

use crate::config::Commands;

mod config;

const MAX_HISTORY: usize = 1000;

#[derive(thiserror::Error, Debug)]
pub enum WalletCliError {
    #[error("RPC error: {0}")]
    RpcError(node_comm::rpc_client::NodeRpcError),
    #[error("Wallet error: {0}")]
    WalletError(wallet::wallet::WalletError),
    #[error("Console IO error: {0}")]
    ConsoleIoError(std::io::Error),
    #[error("Cookie file {0} read error: {1}. Please make sure the node is started.")]
    CookieFileReadError(PathBuf, std::io::Error),
    #[error("Prepare data dir error: {0}")]
    PrepareData(PrepareDataDirError),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
}

fn create_wallet(
    chain_config: Arc<ChainConfig>,
    db: Arc<wallet_storage::Store<wallet_storage::DefaultBackend>>,
    theme: &ColorfulTheme,
) -> Result<wallet::wallet::Wallet<wallet_storage::DefaultBackend>, WalletCliError> {
    let menmonic: String = dialoguer::Input::with_theme(theme)
        .with_prompt("Mnemonic")
        .interact_text()
        .map_err(WalletCliError::ConsoleIoError)?;

    wallet::wallet::Wallet::new_wallet(Arc::clone(&chain_config), db, &menmonic, None)
        .map_err(WalletCliError::WalletError)
}

fn load_wallet(
    chain_config: Arc<ChainConfig>,
    db: Arc<wallet_storage::Store<wallet_storage::DefaultBackend>>,
) -> Result<wallet::wallet::Wallet<wallet_storage::DefaultBackend>, WalletCliError> {
    wallet::wallet::Wallet::load_wallet(Arc::clone(&chain_config), db)
        .map_err(WalletCliError::WalletError)
}

async fn run() -> Result<(), WalletCliError> {
    logging::init_logging::<&std::path::Path>(None);

    let args = config::WalletCliArgs::parse();
    let config = config::WalletCliConfig::from_args(args)?;
    let chain_config = Arc::new(common::chain::config::Builder::new(config.chain_type).build());

    let db = wallet::wallet::open_or_create_wallet_file(&config.wallet_file)
        .map_err(WalletCliError::WalletError)?;

    let theme = ColorfulTheme::default();

    let _wallet = match config.command {
        Some(Commands::CreateWallet {}) => create_wallet(chain_config, db, &theme)?,
        None => load_wallet(chain_config, db)?,
    };

    let rpc_client = make_rpc_client(
        config.rpc_address,
        Some((&config.rpc_username, &config.rpc_password)),
    )
    .await
    .map_err(WalletCliError::RpcError)?;
    println!("Best block id: {:?}", rpc_client.get_best_block_id().await);

    let mut history = CliHistory::default();

    loop {
        if let Ok(cmd) = dialoguer::Input::<String>::with_theme(&theme)
            .with_prompt("mintlayer")
            .history_with(&mut history)
            .interact_text()
        {
            if cmd == "exit" {
                return Ok(());
            }
            println!("Entered {}", cmd);
        }
    }
}

struct CliHistory {
    max: usize,
    history: VecDeque<String>,
}

impl Default for CliHistory {
    fn default() -> Self {
        // TODO: Read history from a file
        CliHistory {
            max: MAX_HISTORY,
            history: VecDeque::new(),
        }
    }
}

impl<T: ToString> History<T> for CliHistory {
    fn read(&self, pos: usize) -> Option<String> {
        self.history.get(pos).cloned()
    }

    fn write(&mut self, val: &T) {
        if self.history.len() == self.max {
            self.history.pop_back();
        }
        self.history.push_front(val.to_string());
    }
}

#[tokio::main]
async fn main() {
    run().await.unwrap_or_else(|err| {
        eprintln!("wallet-cli launch failed: {err}");
        std::process::exit(1)
    })
}

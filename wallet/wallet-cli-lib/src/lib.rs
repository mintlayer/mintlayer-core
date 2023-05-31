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

mod cli_event_loop;
mod commands;
pub mod config;
pub mod console;
pub mod errors;
mod repl;

use std::{net::SocketAddr, str::FromStr, sync::Arc};

use common::chain::config::ChainType;
use config::WalletCliArgs;
use console::{ConsoleInput, ConsoleOutput};
use errors::WalletCliError;
use tokio::sync::mpsc;
use utils::{
    cookie::{load_cookie, COOKIE_FILENAME},
    default_data_dir::default_data_dir_for_chain,
};

enum Mode {
    Interactive {
        logger: repl::interactive::log::InteractiveLogger,
    },
    NonInteractive,
    CommandsList {
        file_input: console::FileInput,
    },
}

pub async fn run(
    console: impl ConsoleInput + ConsoleOutput,
    args: config::WalletCliArgs,
) -> Result<(), WalletCliError> {
    let WalletCliArgs {
        network,
        wallet_file,
        rpc_address,
        rpc_cookie_file,
        rpc_username,
        rpc_password,
        commands_file,
        history_file,
        exit_on_error,
        vi_mode,
    } = args;

    let mode = if let Some(file_path) = commands_file {
        repl::non_interactive::log::init();
        let file_input = console::FileInput::new(file_path)?;
        Mode::CommandsList { file_input }
    } else if console.is_tty() {
        let logger = repl::interactive::log::InteractiveLogger::init();
        Mode::Interactive { logger }
    } else {
        repl::non_interactive::log::init();
        Mode::NonInteractive
    };

    let chain_type: ChainType = network.into();
    let chain_config = Arc::new(common::chain::config::Builder::new(chain_type).build());

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

    let rpc_client =
        wallet_controller::make_rpc_client(rpc_address, Some((&rpc_username, &rpc_password)))
            .await
            .map_err(WalletCliError::RpcError)?;

    let mut controller_opt = None;

    if let Some(wallet_path) = wallet_file {
        commands::handle_wallet_command(
            &chain_config,
            &rpc_client,
            &mut controller_opt,
            commands::WalletCommand::OpenWallet { wallet_path },
        )
        .await?;
    }

    let (event_tx, event_rx) = mpsc::unbounded_channel();

    // Run a blocking loop in a separate thread
    let repl_handle = std::thread::spawn(move || match mode {
        Mode::Interactive { logger } => repl::interactive::run(
            console,
            event_tx,
            exit_on_error.unwrap_or(false),
            logger,
            history_file,
            vi_mode,
        ),
        Mode::NonInteractive => repl::non_interactive::run(
            console.clone(),
            console,
            event_tx,
            exit_on_error.unwrap_or(false),
        ),
        Mode::CommandsList { file_input } => {
            repl::non_interactive::run(file_input, console, event_tx, exit_on_error.unwrap_or(true))
        }
    });

    cli_event_loop::run(&chain_config, &rpc_client, controller_opt, event_rx).await;

    repl_handle.join().expect("Should not panic")
}

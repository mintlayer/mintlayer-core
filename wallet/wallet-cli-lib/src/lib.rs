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

use std::sync::Arc;

use cli_event_loop::Event;
use commands::WalletCommand;
use common::chain::{
    config::{regtest_options::regtest_chain_config, ChainType},
    ChainConfig,
};
use config::{CliArgs, Network};
use console::{ConsoleInput, ConsoleOutput};
use errors::WalletCliError;
use rpc::RpcAuthData;
use tokio::sync::mpsc;
use utils::{cookie::COOKIE_FILENAME, default_data_dir::default_data_dir_for_chain};

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
    input: impl ConsoleInput,
    output: impl ConsoleOutput,
    args: config::WalletCliArgs,
    chain_config: Option<Arc<ChainConfig>>,
) -> Result<(), WalletCliError> {
    let chain_type = args.network.as_ref().map_or(ChainType::Testnet, |network| network.into());
    let chain_config = match chain_config {
        Some(chain_config) => chain_config,
        None => match &args.network {
            Some(Network::Regtest(regtest_options)) => Arc::new(
                regtest_chain_config(&regtest_options.chain_config)
                    .map_err(|err| WalletCliError::InvalidConfig(err.to_string()))?,
            ),
            _ => Arc::new(common::chain::config::Builder::new(chain_type).build()),
        },
    };

    let CliArgs {
        wallet_file,
        wallet_password,
        start_staking,
        rpc_address,
        rpc_cookie_file,
        rpc_username,
        rpc_password,
        commands_file,
        history_file,
        exit_on_error,
        vi_mode,
        in_top_x_mb,
    } = args.cli_args();

    let mode = if let Some(file_path) = commands_file {
        repl::non_interactive::log::init();
        let file_input = console::FileInput::new(file_path)?;
        Mode::CommandsList { file_input }
    } else if input.is_tty() {
        let logger = repl::interactive::log::InteractiveLogger::init();
        Mode::Interactive { logger }
    } else {
        repl::non_interactive::log::init();
        Mode::NonInteractive
    };

    let rpc_auth = match (rpc_cookie_file, rpc_username, rpc_password) {
        (None, None, None) => {
            let cookie_file_path =
                default_data_dir_for_chain(chain_type.name()).join(COOKIE_FILENAME);
            RpcAuthData::Cookie { cookie_file_path }
        }
        (Some(cookie_file_path), None, None) => RpcAuthData::Cookie {
            cookie_file_path: cookie_file_path.into(),
        },
        (None, Some(username), Some(password)) => RpcAuthData::Basic { username, password },
        _ => {
            return Err(WalletCliError::InvalidConfig(
                "Invalid RPC cookie/username/password combination".to_owned(),
            ))
        }
    };

    let (event_tx, event_rx) = mpsc::unbounded_channel();

    let mut startup_command_futures = vec![];
    if let Some(wallet_path) = wallet_file {
        let (res_tx, res_rx) = tokio::sync::oneshot::channel();
        event_tx
            .send(Event::HandleCommand {
                command: WalletCommand::OpenWallet {
                    wallet_path,
                    encryption_password: wallet_password,
                },
                res_tx,
            })
            .expect("should not fail");
        startup_command_futures.push(res_rx);
    }

    if start_staking {
        let (res_tx, res_rx) = tokio::sync::oneshot::channel();
        event_tx
            .send(Event::HandleCommand {
                command: WalletCommand::StartStaking,
                res_tx,
            })
            .expect("should not fail");
        startup_command_futures.push(res_rx);
    }

    // Run a blocking loop in a separate thread
    let repl_handle = std::thread::spawn(move || match mode {
        Mode::Interactive { logger } => repl::interactive::run(
            output,
            event_tx,
            exit_on_error.unwrap_or(false),
            logger,
            history_file,
            vi_mode,
            startup_command_futures,
        ),
        Mode::NonInteractive => repl::non_interactive::run(
            input,
            output,
            event_tx,
            exit_on_error.unwrap_or(false),
            startup_command_futures,
        ),
        Mode::CommandsList { file_input } => repl::non_interactive::run(
            file_input,
            output,
            event_tx,
            exit_on_error.unwrap_or(true),
            startup_command_futures,
        ),
    });

    cli_event_loop::run(&chain_config, event_rx, in_top_x_mb, rpc_address, rpc_auth).await?;

    repl_handle.join().expect("Should not panic")
}

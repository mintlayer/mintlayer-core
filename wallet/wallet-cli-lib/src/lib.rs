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
pub mod config;
pub mod console;
pub mod errors;
mod repl;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use cli_event_loop::Event;
use common::chain::{
    config::{regtest_options::regtest_chain_config, ChainType},
    ChainConfig,
};
use config::{CliArgs, Network};
use console::{ConsoleInput, ConsoleOutput};
use errors::WalletCliError;
use node_comm::{make_cold_wallet_rpc_client, make_rpc_client, rpc_client::ColdWalletClient};
use rpc::RpcAuthData;
use tokio::sync::mpsc;
use utils::{cookie::COOKIE_FILENAME, default_data_dir::default_data_dir_for_chain, ensure};
use wallet_cli_commands::{ManageableWalletCommand, WalletCommand, WalletManagementCommand};
use wallet_rpc_lib::{cmdline::make_wallet_config, config::WalletRpcConfig, types::NodeInterface};

#[cfg(feature = "trezor")]
use wallet_cli_commands::CliHardwareWalletType;

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
) -> Result<(), Box<dyn std::error::Error>> {
    let chain_type = args.network.as_ref().map_or(ChainType::Mainnet, |network| network.into());
    let chain_config = match chain_config {
        Some(chain_config) => chain_config,
        None => match &args.network {
            Some(Network::Regtest(regtest_options)) => Arc::new(
                regtest_chain_config(&regtest_options.chain_config).map_err(|err| {
                    WalletCliError::<ColdWalletClient>::InvalidConfig(err.to_string())
                })?,
            ),
            _ => Arc::new(common::chain::config::Builder::new(chain_type).build()),
        },
    };

    let cli_args = args.cli_args();

    let mode = if let Some(file_path) = &cli_args.commands_file {
        repl::non_interactive::log::init();
        let file_input = console::FileInput::new::<ColdWalletClient>(file_path.clone())?;
        Mode::CommandsList { file_input }
    } else if input.is_tty() {
        let logger = repl::interactive::log::InteractiveLogger::init();
        Mode::Interactive { logger }
    } else {
        repl::non_interactive::log::init();
        Mode::NonInteractive
    };

    let in_top_x_mb = cli_args.in_top_x_mb;
    if cli_args.remote_rpc_wallet_address.is_some() {
        connect_to_rpc_wallet(
            cli_args,
            chain_type,
            mode,
            output,
            input,
            chain_config,
            in_top_x_mb,
        )
        .await
    } else if cli_args.cold_wallet {
        start_cold_wallet(cli_args, mode, output, input, chain_config, in_top_x_mb).await
    } else {
        start_hot_wallet(
            cli_args,
            chain_type,
            mode,
            output,
            input,
            chain_config,
            in_top_x_mb,
        )
        .await
    }
}

async fn start_hot_wallet(
    cli_args: CliArgs,
    chain_type: ChainType,
    mode: Mode,
    output: impl ConsoleOutput,
    input: impl ConsoleInput,
    chain_config: Arc<ChainConfig>,
    in_top_x_mb: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    let rpc_auth = match (
        &cli_args.node_rpc_cookie_file,
        &cli_args.node_rpc_username,
        &cli_args.node_rpc_password,
    ) {
        (None, None, None) => {
            let cookie_file_path =
                default_data_dir_for_chain(chain_type.name()).join(COOKIE_FILENAME);
            RpcAuthData::Cookie { cookie_file_path }
        }
        (Some(cookie_file_path), None, None) => RpcAuthData::Cookie {
            cookie_file_path: cookie_file_path.into(),
        },
        (None, Some(username), Some(password)) => RpcAuthData::Basic {
            username: username.clone(),
            password: password.clone(),
        },
        _ => {
            return Err(Box::new(WalletCliError::<ColdWalletClient>::InvalidConfig(
                "Invalid RPC cookie/username/password combination".to_owned(),
            )))
        }
    };

    let rpc_address = {
        let default_addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            chain_config.default_rpc_port(),
        ))
        .into();
        cli_args.node_rpc_address.clone().unwrap_or(default_addr)
    };

    let no_qr = cli_args.no_qr;
    let (repl_handle, wallet_rpc_config) =
        setup_events_and_repl(cli_args, mode, output, input, event_tx, chain_type)?;

    let node_rpc = make_rpc_client(chain_config.clone(), rpc_address.to_string(), rpc_auth).await?;
    cli_event_loop::run(
        &chain_config.clone(),
        event_rx,
        in_top_x_mb,
        cli_event_loop::WalletType::Local {
            node_rpc,
            wallet_rpc_config,
        },
        false,
        no_qr,
    )
    .await?;
    Ok(repl_handle.join().expect("Should not panic")?)
}

async fn start_cold_wallet(
    cli_args: CliArgs,
    mode: Mode,
    output: impl ConsoleOutput,
    input: impl ConsoleInput,
    chain_config: Arc<ChainConfig>,
    in_top_x_mb: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    let no_qr = cli_args.no_qr;
    let (repl_handle, wallet_rpc_config) = setup_events_and_repl(
        cli_args,
        mode,
        output,
        input,
        event_tx,
        *chain_config.chain_type(),
    )?;

    cli_event_loop::run(
        &chain_config.clone(),
        event_rx,
        in_top_x_mb,
        cli_event_loop::WalletType::Local {
            node_rpc: make_cold_wallet_rpc_client(chain_config),
            wallet_rpc_config,
        },
        true,
        no_qr,
    )
    .await?;
    Ok(repl_handle.join().expect("Should not panic")?)
}

async fn connect_to_rpc_wallet(
    cli_args: CliArgs,
    chain_type: ChainType,
    mode: Mode,
    output: impl ConsoleOutput,
    input: impl ConsoleInput,
    chain_config: Arc<ChainConfig>,
    in_top_x_mb: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    let rpc_auth = match (
        &cli_args.remote_rpc_wallet_cookie_file,
        &cli_args.remote_rpc_wallet_username,
        &cli_args.remote_rpc_wallet_password,
    ) {
        (None, None, None) => {
            ensure!(
                cli_args.remote_rpc_wallet_no_authentication,
                Box::new(WalletCliError::<ColdWalletClient>::InvalidConfig(
                    "At least one RPC cookie/username/password/no-authentication should be specified".to_owned(),
                ))
            );
            RpcAuthData::None
        }
        (Some(cookie_file_path), None, None) => RpcAuthData::Cookie {
            cookie_file_path: cookie_file_path.into(),
        },
        (None, Some(username), Some(password)) => RpcAuthData::Basic {
            username: username.clone(),
            password: password.clone(),
        },
        _ => panic!("Should not happen due to arg constraints"),
    };

    let no_qr = cli_args.no_qr;
    let remote_socket_address = cli_args.remote_rpc_wallet_address.clone().expect("checked");
    let (repl_handle, _wallet_rpc_config) =
        setup_events_and_repl(cli_args, mode, output, input, event_tx, chain_type)?;

    cli_event_loop::run(
        &chain_config.clone(),
        event_rx,
        in_top_x_mb,
        cli_event_loop::WalletType::<ColdWalletClient>::Remote {
            remote_socket_address,
            rpc_auth,
        },
        false,
        no_qr,
    )
    .await?;
    Ok(repl_handle.join().expect("Should not panic")?)
}

#[allow(clippy::type_complexity)]
fn setup_events_and_repl<N: NodeInterface + Send + Sync + 'static>(
    args: CliArgs,
    mode: Mode,
    output: impl ConsoleOutput,
    input: impl ConsoleInput,
    event_tx: mpsc::UnboundedSender<Event<N>>,
    chain_type: ChainType,
) -> Result<
    (
        std::thread::JoinHandle<Result<(), WalletCliError<N>>>,
        Option<WalletRpcConfig>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut startup_command_futures = vec![];
    if let Some(wallet_path) = args.wallet_file {
        let (res_tx, res_rx) = tokio::sync::oneshot::channel();
        event_tx
            .send(Event::HandleCommand {
                command: ManageableWalletCommand::ManagementCommands(
                    WalletManagementCommand::OpenWallet {
                        wallet_path,
                        encryption_password: args.wallet_password,
                        force_change_wallet_type: args.force_change_wallet_type,
                        hardware_wallet: args.hardware_wallet.map(|hw| match hw {
                            #[cfg(feature = "trezor")]
                            wallet_rpc_lib::cmdline::CliHardwareWalletType::Trezor => {
                                CliHardwareWalletType::Trezor
                            }
                        }),
                    },
                ),
                res_tx,
            })
            .expect("should not fail");
        startup_command_futures.push(res_rx);
    }

    if args.start_staking {
        let (res_tx, res_rx) = tokio::sync::oneshot::channel();
        event_tx
            .send(Event::HandleCommand {
                command: ManageableWalletCommand::WalletCommands(WalletCommand::StartStaking),
                res_tx,
            })
            .expect("should not fail");
        startup_command_futures.push(res_rx);
    }

    for account_index in args.start_staking_for_account {
        let (res_tx, res_rx) = tokio::sync::oneshot::channel();
        event_tx
            .send(Event::HandleCommand {
                command: ManageableWalletCommand::WalletCommands(WalletCommand::SelectAccount {
                    account_index,
                }),
                res_tx,
            })
            .expect("should not fail");
        startup_command_futures.push(res_rx);
        let (res_tx, res_rx) = tokio::sync::oneshot::channel();
        event_tx
            .send(Event::HandleCommand {
                command: ManageableWalletCommand::WalletCommands(WalletCommand::StartStaking),
                res_tx,
            })
            .expect("should not fail");
        startup_command_futures.push(res_rx);
    }

    let wallet_rpc_config = if args.enable_wallet_rpc_interface {
        Some(make_wallet_config(
            args.wallet_rpc_cookie_file,
            args.wallet_rpc_username,
            args.wallet_rpc_password,
            args.wallet_rpc_no_authentication,
            args.wallet_rpc_bind_address,
            chain_type,
        )?)
    } else {
        None
    };

    // Run a blocking loop in a separate thread
    let repl = std::thread::spawn(move || match mode {
        Mode::Interactive { logger } => repl::interactive::run(
            output,
            event_tx,
            args.exit_on_error.unwrap_or(false),
            logger,
            args.history_file,
            args.vi_mode,
            startup_command_futures,
            args.cold_wallet,
        ),
        Mode::NonInteractive => repl::non_interactive::run(
            input,
            output,
            event_tx,
            args.exit_on_error.unwrap_or(false),
            args.cold_wallet,
            startup_command_futures,
        ),
        Mode::CommandsList { file_input } => repl::non_interactive::run(
            file_input,
            output,
            event_tx,
            args.exit_on_error.unwrap_or(true),
            args.cold_wallet,
            startup_command_futures,
        ),
    });

    Ok((repl, wallet_rpc_config))
}

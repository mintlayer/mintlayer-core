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

use std::{fmt::Debug, sync::Arc};

use common::chain::ChainConfig;
use tokio::sync::{mpsc, oneshot};
use wallet_cli_commands::{CommandHandler, ConsoleCommand, WalletCommand};
use wallet_rpc_client::{handles_client::WalletRpcHandlesClient, rpc_client::ClientWalletRpc};
use wallet_rpc_lib::types::{ControllerConfig, NodeInterface};
use wallet_rpc_lib::{
    config::WalletRpcConfig, ColdWalletRpcServer, WalletEventsRpcServer, WalletRpc,
    WalletRpcServer, WalletService,
};

use crate::errors::WalletCliError;

#[derive(Debug)]
pub enum Event<N: NodeInterface> {
    HandleCommand {
        command: WalletCommand,
        res_tx: oneshot::Sender<Result<ConsoleCommand, WalletCliError<N>>>,
    },
}

pub enum WalletType<N> {
    Local {
        node_rpc: N,
        wallet_rpc_config: Option<WalletRpcConfig>,
    },
    Remote {
        remote_socket_address: String,
        rpc_auth: rpc::RpcAuthData,
    },
}

pub async fn run<N: NodeInterface + Clone + Send + Sync + 'static + Debug>(
    chain_config: &Arc<ChainConfig>,
    mut event_rx: mpsc::UnboundedReceiver<Event<N>>,
    in_top_x_mb: usize,
    wallet_type: WalletType<N>,
    cold_wallet: bool,
) -> Result<(), WalletCliError<N>> {
    match wallet_type {
        WalletType::Local {
            node_rpc,
            wallet_rpc_config,
        } => {
            let wallet_service =
                WalletService::start(chain_config.clone(), None, false, vec![], node_rpc)
                    .await
                    .map_err(|err| WalletCliError::InvalidConfig(err.to_string()))?;

            let wallet_handle = wallet_service.handle();
            let node_rpc = wallet_service.node_rpc().clone();
            let chain_config = wallet_service.chain_config().clone();

            let wallet_rpc = WalletRpc::new(wallet_handle, node_rpc.clone(), chain_config.clone());
            let server_rpc = if let Some(rpc_config) = wallet_rpc_config {
                let builder = rpc::Builder::new(rpc_config.bind_addr, rpc_config.auth_credentials)
                    .with_method_list("list_methods")
                    .register(ColdWalletRpcServer::into_rpc(wallet_rpc.clone()));
                let server_rpc = if cold_wallet {
                    builder
                } else {
                    builder
                        .register(WalletRpcServer::into_rpc(wallet_rpc.clone()))
                        .register(WalletEventsRpcServer::into_rpc(wallet_rpc.clone()))
                }
                .build()
                .await
                .map_err(|err| WalletCliError::InvalidConfig(err.to_string()))?;

                Some(server_rpc)
            } else {
                None
            };
            let wallet = WalletRpcHandlesClient::new(wallet_rpc, server_rpc);

            let mut command_handler = CommandHandler::new(
                ControllerConfig {
                    in_top_x_mb,
                    broadcast_to_mempool: true,
                },
                wallet,
            )
            .await;

            loop {
                tokio::select! {
                    cmd = event_rx.recv() => {
                        if let Some(Event::HandleCommand { command, res_tx }) = cmd {
                            let res = command_handler.handle_wallet_command(&chain_config, command).await;
                            let _ = res_tx.send(res.map_err(WalletCliError::WalletCommandError));
                        } else {
                            return Ok(());
                        }
                    }
                    _ = command_handler.rpc_completed() => {
                            return Ok(());
                    }
                }
            }
        }
        WalletType::Remote {
            rpc_auth,
            remote_socket_address,
        } => {
            let wallet = ClientWalletRpc::new(remote_socket_address, rpc_auth).await?;

            let mut command_handler = CommandHandler::new(
                ControllerConfig {
                    in_top_x_mb,
                    broadcast_to_mempool: true,
                },
                wallet,
            )
            .await;

            loop {
                tokio::select! {
                    cmd = event_rx.recv() => {
                        if let Some(Event::HandleCommand { command, res_tx }) = cmd {
                            let res = command_handler.handle_wallet_command(chain_config, command).await;
                            let _ = res_tx.send(res.map_err(WalletCliError::WalletCommandError));
                        } else {
                            return Ok(());
                        }
                    }
                    _ = command_handler.rpc_completed() => {
                            return Ok(());
                    }
                }
            }
        }
    };
}

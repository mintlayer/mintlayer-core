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

pub mod cmdline;
pub mod config;
mod rpc;
mod service;

#[cfg(feature = "trezor")]
use rpc::types::HardwareWalletType;
pub use rpc::{
    types, ColdWalletRpcClient, ColdWalletRpcDescription, ColdWalletRpcServer, RpcCreds, RpcError,
    WalletEventsRpcServer, WalletRpc, WalletRpcClient, WalletRpcDescription, WalletRpcServer,
};
pub use service::{Event, EventStream, TxState, WalletHandle, /* WalletResult, */ WalletService,};
use wallet_controller::{NodeInterface, NodeRpcClient};
#[cfg(feature = "trezor")]
use wallet_types::wallet_type::WalletType;

use std::{fmt::Debug, time::Duration};

pub use config::WalletServiceConfig;
use config::{NodeRpc, WalletRpcConfig};
use logging::log;

use utils::shallow_clone::ShallowClone;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(thiserror::Error, Debug)]
pub enum StartupError<N: NodeInterface> {
    #[error(transparent)]
    WalletService(#[from] service::InitError<N>),

    #[error("Failed to start RPC server: {0}")]
    Rpc(anyhow::Error),
}

/// Run a wallet daemon with RPC interface
pub async fn run(
    wallet_config: WalletServiceConfig,
    rpc_config: WalletRpcConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match wallet_config.node_rpc.clone() {
        NodeRpc::HotWallet {
            node_rpc_address,
            node_auth_data,
        } => {
            let rpc_address = {
                let default_addr = || {
                    format!(
                        "127.0.0.1:{}",
                        wallet_config.chain_config.default_rpc_port()
                    )
                };
                node_rpc_address.unwrap_or_else(default_addr)
            };
            let node_rpc = wallet_controller::make_rpc_client(
                wallet_config.chain_config.clone(),
                rpc_address,
                node_auth_data,
            )
            .await
            .map_err(|err| {
                StartupError::WalletService(service::InitError::<NodeRpcClient>::NodeRpc(err))
            })?;

            let (wallet_service, rpc_server) =
                start_services(wallet_config, rpc_config, node_rpc, false).await?;
            wait_for_shutdown(wallet_service, rpc_server).await;
        }
        NodeRpc::ColdWallet => {
            let node_rpc =
                wallet_controller::make_cold_wallet_rpc_client(wallet_config.chain_config.clone());
            let (wallet_service, rpc_server) =
                start_services(wallet_config, rpc_config, node_rpc, true).await?;
            wait_for_shutdown(wallet_service, rpc_server).await;
        }
    }

    Ok(())
}

pub async fn start_services<N>(
    wallet_config: WalletServiceConfig,
    rpc_config: WalletRpcConfig,
    node_rpc: N,
    cold_wallet: bool,
) -> Result<(WalletService<N>, rpc::Rpc), StartupError<N>>
where
    N: NodeInterface + Clone + Sync + Send + 'static + Debug,
{
    let wallet_type = wallet_config.hardware_wallet_type.map_or_else(
        || node_rpc.is_cold_wallet_node().into(),
        |hw| match hw {
            #[cfg(feature = "trezor")]
            HardwareWalletType::Trezor => WalletType::Trezor,
        },
    );
    // Start the wallet service
    let wallet_service = WalletService::start(
        wallet_config.chain_config,
        wallet_config.wallet_file.map(|file| (file, wallet_type)),
        wallet_config.force_change_wallet_type,
        wallet_config.start_staking_for_account,
        node_rpc,
    )
    .await?;

    // Start the RPC server
    let rpc_server = {
        let wallet_handle = wallet_service.handle().shallow_clone();
        let node_rpc = wallet_service.node_rpc().clone();
        let chain_config = wallet_service.chain_config().shallow_clone();
        rpc::start(
            wallet_handle,
            node_rpc,
            rpc_config,
            chain_config,
            cold_wallet,
        )
        .await
        .map_err(StartupError::Rpc)?
    };

    Ok((wallet_service, rpc_server))
}

/// Run a wallet daemon with RPC interface
pub async fn wait_for_shutdown<N>(wallet_service: WalletService<N>, rpc_server: rpc::Rpc)
where
    N: NodeInterface + Clone + Send + Sync + 'static,
{
    // Start the wallet service
    let wallet_handle = wallet_service.handle();

    // Possible ways the program may quit as futures.
    let ctrl_c_signal = std::pin::pin!(async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => (),
            Err(err) => {
                log::warn!("Failed to initialize signal handler: {err}");
                futures::future::pending().await
            }
        }
    });

    let service_join_handle = std::pin::pin!(wallet_service.join());

    // Wait for an external termination or for the service task to end
    let shutdown_init = futures::future::select(ctrl_c_signal, service_join_handle).await;
    log::info!("Wallet RPC service shutdown initiated");

    // Set up the shutdown sequence future
    let shutdown_sequence = async {
        let task_result = match shutdown_init {
            futures::future::Either::Left(((), service_join_handle)) => {
                // Shutdown signal triggered externally, now try to cleanly shut down the service
                if let Err(err) = wallet_handle.stop() {
                    log::warn!("Shutdown request submission failed: {err}");
                }
                service_join_handle.await
            }
            futures::future::Either::Right((task_result, _ctrl_c)) => {
                // Service terminated on its own, just return the outcome
                task_result
            }
        };

        // Also stop the RPC server
        rpc_server.shutdown().await;

        task_result
    };

    // Run the shutdown sequence under a timeout
    match tokio::time::timeout(SHUTDOWN_TIMEOUT, shutdown_sequence).await {
        Ok(Ok(())) => log::trace!("Successful shutdown"),
        Ok(Err(err)) => log::warn!("Wallet service failed during shutdown: {err}"),
        Err(elapsed) => log::warn!("Shutdown timed out in {elapsed}"),
    }

    log::info!("Wallet RPC service terminated");
}

pub fn rpc_interface_description() -> ::rpc::description::Interface {
    use ::rpc::description::Described;
    ::rpc::description::Interface::from_iter([
        WalletRpcDescription::DESCRIPTION,
        ColdWalletRpcDescription::DESCRIPTION,
    ])
}

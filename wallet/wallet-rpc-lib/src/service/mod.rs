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

mod handle;
mod worker;

use std::sync::Arc;

use common::chain::ChainConfig;
use utils::shallow_clone::ShallowClone;
pub use wallet_controller::NodeRpcClient;

pub use worker::{WalletController, WalletControllerError, WalletManagement};

pub use handle::WalletHandle;

pub type WalletResult<T> = Result<T, WalletControllerError>;

/// Wallet service
pub struct WalletService {
    task: tokio::task::JoinHandle<()>,
    command_tx: worker::CommandSender,
    node_rpc: NodeRpcClient,
    chain_config: Arc<ChainConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error(transparent)]
    Wallet(#[from] wallet::WalletError),
    #[error(transparent)]
    NodeRpc(#[from] node_comm::rpc_client::NodeRpcError),
    #[error(transparent)]
    Controller(#[from] WalletControllerError),
}

impl WalletService {
    pub async fn start(config: crate::WalletServiceConfig) -> Result<Self, InitError> {
        let chain_config = config.chain_config;

        let node_rpc = {
            let rpc_address = {
                let default_addr = || format!("127.0.0.1:{}", chain_config.default_rpc_port());
                config.node_rpc_address.unwrap_or_else(default_addr)
            };

            wallet_controller::make_rpc_client(rpc_address, config.node_credentials).await?
        };

        let controller = if let Some(wallet_file) = &config.wallet_file {
            let wallet = {
                // TODO: Allow user to set password (config file only)
                let wallet_password = None;
                WalletController::open_wallet(
                    chain_config.shallow_clone(),
                    wallet_file,
                    wallet_password,
                )?
            };

            Some(
                WalletController::new(
                    chain_config.shallow_clone(),
                    node_rpc.clone(),
                    wallet,
                    wallet::wallet_events::WalletEventsNoOp,
                )
                .await?,
            )
        } else {
            None
        };

        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();

        let task = worker::WalletWorker::spawn(
            controller,
            command_rx,
            chain_config.clone(),
            node_rpc.clone(),
        );

        Ok(WalletService {
            task,
            command_tx,
            node_rpc,
            chain_config,
        })
    }

    pub fn node_rpc(&self) -> &NodeRpcClient {
        &self.node_rpc
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
    }

    /// Get wallet service handle
    pub fn handle(&self) -> WalletHandle {
        WalletHandle::new(worker::CommandSender::clone(&self.command_tx))
    }

    /// Wait for the service to shut down
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.task.await
    }
}

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

mod events;
mod handle;
mod worker;

use std::{path::PathBuf, sync::Arc};

use common::chain::ChainConfig;
use node_comm::rpc_client::MaybeDummyNode;
use rpc::RpcAuthData;
use utils::shallow_clone::ShallowClone;

pub use events::{Event, TxState};
pub use handle::{EventStream, SubmitError, WalletHandle};
pub use worker::{CreatedWallet, WalletController, WalletControllerError};

use events::WalletServiceEvents;

pub type WalletResult<T> = Result<T, WalletControllerError>;

/// Wallet service
pub struct WalletService {
    task: tokio::task::JoinHandle<()>,
    command_tx: worker::CommandSender,
    node_rpc: MaybeDummyNode,
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
    pub async fn start(
        chain_config: Arc<ChainConfig>,
        wallet_file: Option<PathBuf>,
        node_config: Option<(Option<String>, RpcAuthData)>,
    ) -> Result<Self, InitError> {
        let node_rpc = wallet_controller::make_opt_rpc_client(
            node_config.map(|(addr, auth)| {
                let rpc_address = {
                    let default_addr = || format!("127.0.0.1:{}", chain_config.default_rpc_port());
                    addr.unwrap_or_else(default_addr)
                };

                (rpc_address, auth)
            }),
            chain_config.clone(),
        )
        .await?;

        let (wallet_events, events_rx) = WalletServiceEvents::new();
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();

        let controller = if let Some(wallet_file) = &wallet_file {
            let wallet = {
                // TODO: Allow user to set password (config file only)
                let wallet_password = None;
                WalletController::open_wallet(
                    chain_config.shallow_clone(),
                    wallet_file,
                    wallet_password,
                )?
            };

            let controller = WalletController::new(
                chain_config.shallow_clone(),
                node_rpc.clone(),
                wallet,
                wallet_events.clone(),
            )
            .await?;

            Some(controller)
        } else {
            None
        };

        let task = worker::WalletWorker::spawn(
            controller,
            chain_config.clone(),
            node_rpc.clone(),
            command_rx,
            events_rx,
            wallet_events,
        );

        Ok(WalletService {
            task,
            command_tx,
            node_rpc,
            chain_config,
        })
    }

    pub fn node_rpc(&self) -> &MaybeDummyNode {
        &self.node_rpc
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
    }

    /// Get wallet service handle
    pub fn handle(&self) -> WalletHandle {
        handle::create(worker::CommandSender::clone(&self.command_tx))
    }

    /// Wait for the service to shut down
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.task.await
    }
}

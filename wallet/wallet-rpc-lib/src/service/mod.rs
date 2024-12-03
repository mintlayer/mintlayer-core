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
use crypto::key::hdkd::u31::U31;
use utils::shallow_clone::ShallowClone;

pub use events::{Event, TxState};
pub use handle::{EventStream, SubmitError, WalletHandle};
use wallet_controller::{ControllerConfig, NodeInterface};
use wallet_types::wallet_type::WalletType;
pub use worker::{WalletController, WalletControllerError};

use events::WalletServiceEvents;

// pub type WalletResult<T> = Result<T, WalletControllerError>;

/// Wallet service
pub struct WalletService<N> {
    task: tokio::task::JoinHandle<()>,
    command_tx: worker::CommandSender<N>,
    node_rpc: N,
    chain_config: Arc<ChainConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum InitError<N: NodeInterface> {
    #[error(transparent)]
    Wallet(#[from] wallet::WalletError),
    #[error(transparent)]
    NodeRpc(#[from] node_comm::rpc_client::NodeRpcError),
    #[error(transparent)]
    Controller(#[from] WalletControllerError<N>),
}

impl<N> WalletService<N>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
{
    pub async fn start(
        chain_config: Arc<ChainConfig>,
        wallet_file: Option<(PathBuf, WalletType)>,
        force_change_wallet_type: bool,
        start_staking_for_account: Vec<U31>,
        node_rpc: N,
    ) -> Result<Self, InitError<N>> {
        let (wallet_events, events_rx) = WalletServiceEvents::new();
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();

        let controller = if let Some((wallet_file, open_as_wallet_type)) = &wallet_file {
            let wallet = {
                // TODO: Allow user to set password (config file only)
                let wallet_password = None;
                WalletController::open_wallet(
                    chain_config.shallow_clone(),
                    wallet_file,
                    wallet_password,
                    node_rpc.is_cold_wallet_node(),
                    force_change_wallet_type,
                    *open_as_wallet_type,
                )?
            };

            let mut controller = WalletController::new(
                chain_config.shallow_clone(),
                node_rpc.clone(),
                wallet,
                wallet_events.clone(),
            )
            .await?;

            for account_index in start_staking_for_account {
                // Irrelevant for staking
                let config = ControllerConfig {
                    in_top_x_mb: 5,
                    broadcast_to_mempool: true,
                };
                controller.synced_controller(account_index, config).await?.start_staking()?;
            }

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

    pub fn node_rpc(&self) -> &N {
        &self.node_rpc
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
    }

    /// Get wallet service handle
    pub fn handle(&self) -> WalletHandle<N> {
        handle::create(worker::CommandSender::clone(&self.command_tx))
    }

    /// Wait for the service to shut down
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.task.await
    }
}

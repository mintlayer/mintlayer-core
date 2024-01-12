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

use std::{ops::ControlFlow, path::PathBuf, sync::Arc};

use common::chain::ChainConfig;
use futures::{future::BoxFuture, never::Never};
use tokio::{sync::mpsc, task::JoinHandle};

use logging::log;
use wallet::wallet::Mnemonic;
use wallet_controller::{ControllerError, NodeInterface, NodeRpcClient};
use wallet_types::seed_phrase::StoreSeedPhrase;

use crate::types::RpcError;

pub type WalletController =
    wallet_controller::RpcController<wallet::wallet_events::WalletEventsNoOp>;
pub type WalletControllerError =
    wallet_controller::ControllerError<wallet_controller::NodeRpcClient>;
pub type CommandReceiver = mpsc::UnboundedReceiver<WalletCommand>;
pub type CommandSender = mpsc::UnboundedSender<WalletCommand>;

type CommandFn = dyn Send + FnOnce(&mut Option<WalletController>) -> BoxFuture<()>;
type ManageFn = dyn Send + FnOnce(&mut WalletWorker) -> BoxFuture<()>;

pub enum WalletCommand {
    /// Make the controller perform an action
    Call(Box<CommandFn>),

    /// Manage the Wallet itself, i.e. Create/Open/Close
    Manage(Box<ManageFn>),

    /// Shutdown the wallet service task
    Stop,
}

pub enum CreatedWallet {
    UserProvidedMenmonic,
    NewlyGeneratedMnemonic(Mnemonic),
}

/// Represents the wallet worker task. It handles external commands and keeps the wallet in sync.
pub struct WalletWorker {
    controller: Option<WalletController>,
    command_rx: CommandReceiver,
    chain_config: Arc<ChainConfig>,
    node_rpc: NodeRpcClient,
}

impl WalletWorker {
    fn new(
        controller: Option<WalletController>,
        command_rx: CommandReceiver,
        chain_config: Arc<ChainConfig>,
        node_rpc: NodeRpcClient,
    ) -> Self {
        Self {
            controller,
            command_rx,
            chain_config,
            node_rpc,
        }
    }

    pub fn spawn(
        controller: Option<WalletController>,
        request_rx: CommandReceiver,
        chain_config: Arc<ChainConfig>,
        node_rpc: NodeRpcClient,
    ) -> JoinHandle<()> {
        tokio::spawn(Self::new(controller, request_rx, chain_config, node_rpc).event_loop())
    }

    async fn event_loop(mut self) {
        loop {
            tokio::select! {
                // Give priority to user request processing
                biased;

                // Process user command
                command = self.command_rx.recv() => {
                    match self.process_command(command).await {
                        ControlFlow::Continue(()) => (),
                        ControlFlow::Break(()) => break,
                    }
                }

                // Background wallet sync if there's nothing else to do
                result = Self::background_task(&mut self.controller) => {
                    match result {
                        Ok(never) => match never {},
                        Err(err) => log::error!("Wallet syncing error: {err}"),
                    }
                },
            }
        }
    }

    pub async fn process_command(&mut self, command: Option<WalletCommand>) -> ControlFlow<()> {
        match command {
            Some(WalletCommand::Call(call)) => {
                call(&mut self.controller).await;
                ControlFlow::Continue(())
            }
            Some(WalletCommand::Manage(call)) => {
                call(self).await;
                ControlFlow::Continue(())
            }
            Some(WalletCommand::Stop) => {
                log::info!("Wallet service terminating upon user request");
                ControlFlow::Break(())
            }
            None => {
                log::warn!("Wallet service channel closed; stopping");
                ControlFlow::Break(())
            }
        }
    }

    pub fn close_wallet(&mut self) -> Result<(), ControllerError<NodeRpcClient>> {
        self.controller = None;
        Ok(())
    }

    pub async fn open_wallet(
        &mut self,
        wallet_path: PathBuf,
        password: Option<String>,
    ) -> Result<(), ControllerError<NodeRpcClient>> {
        let wallet =
            WalletController::open_wallet(self.chain_config.clone(), wallet_path, password)?;

        let controller = WalletController::new(
            self.chain_config.clone(),
            self.node_rpc.clone(),
            wallet,
            wallet::wallet_events::WalletEventsNoOp,
        )
        .await?;
        self.controller.replace(controller);

        Ok(())
    }
    pub async fn create_wallet(
        &mut self,
        wallet_path: PathBuf,
        whether_to_store_seed_phrase: StoreSeedPhrase,
        mnemonic: Option<String>,
    ) -> Result<CreatedWallet, RpcError> {
        // TODO: Support other languages
        let language = wallet::wallet::Language::English;
        let newly_generated_mnemonic = mnemonic.is_none();
        let mnemonic = match &mnemonic {
            Some(mnemonic) => wallet_controller::mnemonic::parse_mnemonic(language, mnemonic)
                .map_err(RpcError::InvalidMnemonic)?,
            None => wallet_controller::mnemonic::generate_new_mnemonic(language),
        };

        let wallet = if newly_generated_mnemonic {
            let info = self.node_rpc.chainstate_info().await.map_err(RpcError::RpcError)?;
            WalletController::create_wallet(
                self.chain_config.clone(),
                wallet_path,
                mnemonic.clone(),
                None,
                whether_to_store_seed_phrase,
                info.best_block_height,
                info.best_block_id,
            )
        } else {
            WalletController::recover_wallet(
                self.chain_config.clone(),
                wallet_path,
                mnemonic.clone(),
                None,
                whether_to_store_seed_phrase,
            )
        }
        .map_err(RpcError::Controller)?;

        let controller = WalletController::new(
            self.chain_config.clone(),
            self.node_rpc.clone(),
            wallet,
            wallet::wallet_events::WalletEventsNoOp,
        )
        .await
        .map_err(RpcError::Controller)?;

        self.controller.replace(controller);

        let result = match newly_generated_mnemonic {
            true => CreatedWallet::NewlyGeneratedMnemonic(mnemonic),
            false => CreatedWallet::UserProvidedMenmonic,
        };
        Ok(result)
    }

    async fn background_task(
        controller_opt: &mut Option<WalletController>,
    ) -> Result<Never, WalletControllerError> {
        match controller_opt.as_mut() {
            Some(controller) => controller.run().await,
            None => std::future::pending().await,
        }
    }
}

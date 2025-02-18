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
use utils_networking::broadcaster::Broadcaster;
use wallet_controller::types::{CreatedWallet, WalletCreationOptions, WalletTypeArgs};
use wallet_controller::{ControllerError, NodeInterface};
use wallet_types::scan_blockchain::ScanBlockchain;
use wallet_types::wallet_type::WalletType;

use crate::types::RpcError;

use crate::Event;

use super::WalletServiceEvents;

pub type WalletController<N> = wallet_controller::RpcController<N, super::WalletServiceEvents>;
pub type WalletControllerError<N> = wallet_controller::ControllerError<N>;
pub type CommandReceiver<N> = mpsc::UnboundedReceiver<WalletCommand<N>>;
pub type CommandSender<N> = mpsc::UnboundedSender<WalletCommand<N>>;
pub type EventStream = utils_networking::broadcaster::Receiver<Event>;

type CommandFn<N> = dyn Send + FnOnce(&mut Option<WalletController<N>>) -> BoxFuture<()>;
type ManageFn<N> = dyn Send + FnOnce(&mut WalletWorker<N>) -> BoxFuture<()>;

/// Commands to control the wallet task
pub enum WalletCommand<N> {
    /// Make the controller perform an action
    Call(Box<CommandFn<N>>),

    /// Manage the Wallet itself, i.e. Create/Open/Close
    Manage(Box<ManageFn<N>>),

    /// Shutdown the wallet service task
    Stop,
}

/// Represents the wallet worker task. It handles external commands and keeps the wallet in sync.
pub struct WalletWorker<N> {
    controller: Option<WalletController<N>>,
    command_rx: CommandReceiver<N>,
    chain_config: Arc<ChainConfig>,
    node_rpc: N,
    events_bcast: Broadcaster<Event>,
    events_rx: mpsc::UnboundedReceiver<Event>,
    wallet_events: WalletServiceEvents,
}

impl<N> WalletWorker<N>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
{
    fn new(
        controller: Option<WalletController<N>>,
        chain_config: Arc<ChainConfig>,
        node_rpc: N,
        command_rx: CommandReceiver<N>,
        events_rx: mpsc::UnboundedReceiver<Event>,
        wallet_events: WalletServiceEvents,
    ) -> Self {
        let events_bcast = Broadcaster::new();
        Self {
            controller,
            command_rx,
            chain_config,
            node_rpc,
            events_bcast,
            events_rx,
            wallet_events,
        }
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

                // Forward events to subscribers
                event = self.events_rx.recv() => {
                    match event {
                        Some(event) => self.events_bcast.broadcast(&event),
                        None => log::warn!("Events channel closed unexpectedly"),
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

    pub async fn process_command(&mut self, command: Option<WalletCommand<N>>) -> ControlFlow<()> {
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

    pub fn close_wallet(&mut self) -> Result<(), ControllerError<N>> {
        utils::ensure!(self.controller.is_some(), ControllerError::NoWallet);
        self.controller = None;
        Ok(())
    }

    pub async fn open_wallet(
        &mut self,
        wallet_path: PathBuf,
        password: Option<String>,
        force_migrate_wallet_type: bool,
        scan_blockchain: ScanBlockchain,
        open_as_wallet_type: WalletType,
    ) -> Result<(), ControllerError<N>> {
        utils::ensure!(
            self.controller.is_none(),
            ControllerError::WalletFileAlreadyOpen
        );

        let wallet = WalletController::open_wallet(
            self.chain_config.clone(),
            wallet_path,
            password,
            self.node_rpc.is_cold_wallet_node(),
            force_migrate_wallet_type,
            open_as_wallet_type,
        )?;

        let controller = if scan_blockchain.should_wait_for_blockchain_scanning() {
            WalletController::new(
                self.chain_config.clone(),
                self.node_rpc.clone(),
                wallet,
                self.wallet_events.clone(),
            )
            .await?
        } else {
            WalletController::new_unsynced(
                self.chain_config.clone(),
                self.node_rpc.clone(),
                wallet,
                self.wallet_events.clone(),
            )
        };
        self.controller.replace(controller);

        Ok(())
    }

    pub async fn create_wallet(
        &mut self,
        wallet_path: PathBuf,
        args: WalletTypeArgs,
        options: WalletCreationOptions,
    ) -> Result<CreatedWallet, RpcError<N>> {
        utils::ensure!(
            self.controller.is_none(),
            ControllerError::WalletFileAlreadyOpen
        );
        let wallet_type = args.wallet_type(self.node_rpc.is_cold_wallet_node());
        let (computed_args, wallet_created) =
            args.parse_or_generate_mnemonic_if_needed().map_err(RpcError::InvalidMnemonic)?;

        let wallet = if options.scan_blockchain.skip_scanning_the_blockchain() {
            let info = self.node_rpc.chainstate_info().await.map_err(RpcError::RpcError)?;
            WalletController::create_wallet(
                self.chain_config.clone(),
                wallet_path,
                computed_args,
                (info.best_block_height, info.best_block_id),
                wallet_type,
                options.overwrite_wallet_file,
            )
        } else {
            WalletController::recover_wallet(
                self.chain_config.clone(),
                wallet_path,
                computed_args,
                wallet_type,
            )
        }
        .map_err(RpcError::Controller)?;

        let controller = if options.scan_blockchain.should_wait_for_blockchain_scanning() {
            WalletController::new(
                self.chain_config.clone(),
                self.node_rpc.clone(),
                wallet,
                self.wallet_events.clone(),
            )
            .await
            .map_err(RpcError::Controller)?
        } else {
            WalletController::new_unsynced(
                self.chain_config.clone(),
                self.node_rpc.clone(),
                wallet,
                self.wallet_events.clone(),
            )
        };

        self.controller.replace(controller);

        Ok(wallet_created)
    }

    pub fn subscribe(&mut self) -> EventStream {
        self.events_bcast.subscribe()
    }

    async fn background_task(
        controller_opt: &mut Option<WalletController<N>>,
    ) -> Result<Never, WalletControllerError<N>> {
        match controller_opt.as_mut() {
            Some(controller) => controller.run().await,
            None => std::future::pending().await,
        }
    }
}

impl<N> WalletWorker<N>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
{
    pub fn spawn(
        controller: Option<WalletController<N>>,
        chain_config: Arc<ChainConfig>,
        node_rpc: N,
        command_rx: CommandReceiver<N>,
        events_rx: mpsc::UnboundedReceiver<Event>,
        wallet_events: WalletServiceEvents,
    ) -> JoinHandle<()> {
        let worker = WalletWorker::new(
            controller,
            chain_config,
            node_rpc,
            command_rx,
            events_rx,
            wallet_events,
        );

        tokio::spawn(worker.event_loop())
    }
}

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
use wallet::signer::SignerProvider;
use wallet::wallet::Mnemonic;
use wallet_controller::{ControllerError, NodeInterface};
use wallet_types::scan_blockchain::ScanBlockchain;
use wallet_types::seed_phrase::StoreSeedPhrase;

use crate::types::RpcError;

use crate::Event;

use super::WalletServiceEvents;

pub type WalletController<N, P> =
    wallet_controller::RpcController<N, super::WalletServiceEvents, P>;
pub type WalletControllerError<N> = wallet_controller::ControllerError<N>;
pub type CommandReceiver<N, P> = mpsc::UnboundedReceiver<WalletCommand<N, P>>;
pub type CommandSender<N, P> = mpsc::UnboundedSender<WalletCommand<N, P>>;
pub type EventStream = utils_networking::broadcaster::Receiver<Event>;

type CommandFn<N, P> = dyn Send + FnOnce(&mut Option<WalletController<N, P>>) -> BoxFuture<()>;
type ManageFn<N, P> = dyn Send + FnOnce(&mut WalletWorker<N, P>) -> BoxFuture<()>;

/// Commands to control the wallet task
pub enum WalletCommand<N, P> {
    /// Make the controller perform an action
    Call(Box<CommandFn<N, P>>),

    /// Manage the Wallet itself, i.e. Create/Open/Close
    Manage(Box<ManageFn<N, P>>),

    /// Shutdown the wallet service task
    Stop,
}

pub enum CreatedWallet {
    UserProvidedMnemonic,
    NewlyGeneratedMnemonic(Mnemonic, Option<String>),
}

/// Represents the wallet worker task. It handles external commands and keeps the wallet in sync.
pub struct WalletWorker<N, P> {
    controller: Option<WalletController<N, P>>,
    command_rx: CommandReceiver<N, P>,
    chain_config: Arc<ChainConfig>,
    node_rpc: N,
    events_bcast: Broadcaster<Event>,
    events_rx: mpsc::UnboundedReceiver<Event>,
    wallet_events: WalletServiceEvents,
}

impl<N, P> WalletWorker<N, P>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
    P: SignerProvider + Sync + Send + 'static,
{
    fn new(
        controller: Option<WalletController<N, P>>,
        chain_config: Arc<ChainConfig>,
        node_rpc: N,
        command_rx: CommandReceiver<N, P>,
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

    pub async fn process_command(
        &mut self,
        command: Option<WalletCommand<N, P>>,
    ) -> ControlFlow<()> {
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
        signer_provider: P,
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
            signer_provider,
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
        whether_to_store_seed_phrase: StoreSeedPhrase,
        mnemonic: Option<String>,
        passphrase: Option<String>,
        scan_blockchain: ScanBlockchain,
        signer_provider: P,
    ) -> Result<CreatedWallet, RpcError<N>> {
        utils::ensure!(
            self.controller.is_none(),
            ControllerError::WalletFileAlreadyOpen
        );
        // TODO: Support other languages
        let language = wallet::wallet::Language::English;
        let newly_generated_mnemonic = mnemonic.is_none();
        let mnemonic = match &mnemonic {
            Some(mnemonic) => wallet_controller::mnemonic::parse_mnemonic(language, mnemonic)
                .map_err(RpcError::InvalidMnemonic)?,
            None => wallet_controller::mnemonic::generate_new_mnemonic(language),
        };
        let passphrase_ref = passphrase.as_ref().map(|x| x.as_ref());

        let wallet =
            if newly_generated_mnemonic || scan_blockchain.skip_scanning_the_blockchain() {
                let info = self.node_rpc.chainstate_info().await.map_err(RpcError::RpcError)?;
                WalletController::create_wallet(
                    self.chain_config.clone(),
                    wallet_path,
                    mnemonic.clone(),
                    passphrase_ref,
                    whether_to_store_seed_phrase,
                    (info.best_block_height, info.best_block_id),
                    self.node_rpc.is_cold_wallet_node(),
                    signer_provider,
                )
            } else {
                WalletController::recover_wallet(
                    self.chain_config.clone(),
                    wallet_path,
                    mnemonic.clone(),
                    passphrase_ref,
                    whether_to_store_seed_phrase,
                    self.node_rpc.is_cold_wallet_node(),
                    signer_provider,
                )
            }
            .map_err(RpcError::Controller)?;

        let controller = if scan_blockchain.should_wait_for_blockchain_scanning() {
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

        let result = match newly_generated_mnemonic {
            true => CreatedWallet::NewlyGeneratedMnemonic(mnemonic, passphrase),
            false => CreatedWallet::UserProvidedMnemonic,
        };
        Ok(result)
    }

    pub fn subscribe(&mut self) -> EventStream {
        self.events_bcast.subscribe()
    }

    async fn background_task(
        controller_opt: &mut Option<WalletController<N, P>>,
    ) -> Result<Never, WalletControllerError<N>> {
        match controller_opt.as_mut() {
            Some(controller) => controller.run().await,
            None => std::future::pending().await,
        }
    }
}

impl<N, P> WalletWorker<N, P>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
    P: SignerProvider + Sync + Send + 'static,
{
    pub fn spawn(
        controller: Option<WalletController<N, P>>,
        chain_config: Arc<ChainConfig>,
        node_rpc: N,
        command_rx: CommandReceiver<N, P>,
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

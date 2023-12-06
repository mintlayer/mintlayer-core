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

use std::ops::ControlFlow;

use futures::{future::BoxFuture, never::Never};
use tokio::{sync::mpsc, task::JoinHandle};

use logging::log;

pub type WalletController =
    wallet_controller::RpcController<wallet::wallet_events::WalletEventsNoOp>;
pub type WalletControllerError =
    wallet_controller::ControllerError<wallet_controller::NodeRpcClient>;
pub type CommandReceiver = mpsc::UnboundedReceiver<WalletCommand>;
pub type CommandSender = mpsc::UnboundedSender<WalletCommand>;

type CommandFn = dyn Send + FnOnce(&mut WalletController) -> BoxFuture<()>;

pub enum WalletCommand {
    /// Make the controller perform an action
    Call(Box<CommandFn>),

    /// Shutdown the wallet service task
    Stop,
}

/// Represents the wallet worker task. It handles external commands and keeps the wallet in sync.
pub struct WalletWorker {
    controller: WalletController,
    command_rx: CommandReceiver,
}

impl WalletWorker {
    fn new(controller: WalletController, command_rx: CommandReceiver) -> Self {
        Self {
            controller,
            command_rx,
        }
    }

    pub fn spawn(controller: WalletController, request_rx: CommandReceiver) -> JoinHandle<()> {
        tokio::spawn(Self::new(controller, request_rx).event_loop())
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

    async fn background_task(
        controller: &mut WalletController,
    ) -> Result<Never, WalletControllerError> {
        controller.run().await
    }
}

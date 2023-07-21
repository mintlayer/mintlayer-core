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

use std::sync::Arc;

use common::chain::ChainConfig;
use tokio::sync::{mpsc, oneshot};
use wallet::wallet_events::WalletEventsNoOp;
use wallet_controller::{NodeRpcClient, RpcController};

use crate::{
    commands::{CommandHandler, ConsoleCommand, WalletCommand},
    errors::WalletCliError,
};

#[derive(Debug)]
pub enum Event {
    HandleCommand {
        command: WalletCommand,
        res_tx: oneshot::Sender<Result<ConsoleCommand, WalletCliError>>,
    },
}

pub async fn run(
    chain_config: &Arc<ChainConfig>,
    rpc_client: &NodeRpcClient,
    mut controller_opt: Option<RpcController>,
    mut event_rx: mpsc::UnboundedReceiver<Event>,
) {
    let mut command_handler = CommandHandler::new();

    loop {
        let background_task = async {
            match controller_opt.as_mut() {
                Some(controller) => controller.run(&mut WalletEventsNoOp).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            event_opt = event_rx.recv() => {
                match event_opt {
                    Some(Event::HandleCommand { command, res_tx }) => {
                        let res = command_handler.handle_wallet_command(chain_config, rpc_client, &mut controller_opt, command).await;
                        let _ = res_tx.send(res);
                    },
                    None => return,
                }
            }
            _ = background_task => {}
        }
    }
}

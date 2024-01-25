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
use wallet_controller::{ControllerConfig, NodeInterface};
use wallet_rpc_lib::config::WalletRpcConfig;

use crate::{
    commands::{CommandHandler, ConsoleCommand, WalletCommand},
    errors::WalletCliError,
};

#[derive(Debug)]
pub enum Event<N: NodeInterface> {
    HandleCommand {
        command: WalletCommand,
        res_tx: oneshot::Sender<Result<ConsoleCommand, WalletCliError<N>>>,
    },
}

pub async fn run<N: NodeInterface + Clone + Send + Sync + 'static + Debug>(
    chain_config: &Arc<ChainConfig>,
    mut event_rx: mpsc::UnboundedReceiver<Event<N>>,
    in_top_x_mb: usize,
    node_rpc: N,
    wallet_rpc_config: Option<WalletRpcConfig>,
) -> Result<(), WalletCliError<N>> {
    let mut command_handler = CommandHandler::new(
        ControllerConfig { in_top_x_mb },
        chain_config.clone(),
        node_rpc,
        wallet_rpc_config,
    )
    .await?;

    loop {
        tokio::select! {
            cmd = event_rx.recv() => {
                if let Some(Event::HandleCommand { command, res_tx }) = cmd {
                    let res = command_handler.handle_wallet_command(chain_config, command).await;
                    let _ = res_tx.send(res);
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

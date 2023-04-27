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

use tokio::sync::{mpsc, oneshot};
use wallet_controller::RpcController;

use crate::{
    commands::{handle_wallet_command, ConsoleCommand, WalletCommand},
    errors::WalletCliError,
};

#[derive(Debug)]
pub enum Event {
    HandleCommand {
        command: WalletCommand,
        res_tx: oneshot::Sender<Result<ConsoleCommand, WalletCliError>>,
    },
}

async fn handle_event(controller: &mut RpcController, event: Event) {
    match event {
        Event::HandleCommand { command, res_tx } => {
            let res = handle_wallet_command(controller, command).await;
            let _ = res_tx.send(res);
        }
    }
}

pub async fn run(mut controller: RpcController, mut event_rx: mpsc::UnboundedReceiver<Event>) {
    loop {
        tokio::select! {
            event_opt = event_rx.recv() => {
                match event_opt {
                    Some(event) => {
                        handle_event(&mut controller, event).await;
                    },
                    None => return,
                }
            }
            _ = controller.run_sync() => {}
        }
    }
}

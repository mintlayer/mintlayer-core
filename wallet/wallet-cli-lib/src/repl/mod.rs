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

pub mod interactive;
pub mod non_interactive;

use tokio::sync::mpsc;
use wallet_cli_commands::{ConsoleCommand, ManageableWalletCommand};
use wallet_rpc_lib::types::NodeInterface;

use crate::{cli_event_loop::Event, errors::WalletCliError};

fn run_command_blocking<N: NodeInterface>(
    event_tx: &mpsc::UnboundedSender<Event<N>>,
    command: ManageableWalletCommand,
) -> Result<ConsoleCommand, WalletCliError<N>> {
    let (res_tx, res_rx) = tokio::sync::oneshot::channel();
    // channel is closed so exit
    if event_tx.send(Event::HandleCommand { command, res_tx }).is_err() {
        return Ok(ConsoleCommand::Exit);
    }

    res_rx.blocking_recv().expect("Channel must be open")
}

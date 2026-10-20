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

pub mod exec;
pub mod interactive;
pub mod non_interactive;

use tokio::sync::mpsc;
use wallet_cli_commands::{ConsoleCommand, ManageableWalletCommand};
use wallet_rpc_lib::types::NodeInterface;

use crate::{cli_event_loop::Event, errors::WalletCliError};

/// Refuse state-changing commands in non-interactive modes unless the user
/// passed `--yes`. The mode name is embedded in the error message.
pub(crate) fn confirmation_gate<N: NodeInterface>(
    command: &ManageableWalletCommand,
    assume_yes: bool,
    mode_name: &str,
) -> Result<(), WalletCliError<N>> {
    if let Some(question) = wallet_cli_commands::confirm::confirmation_prompt(command)
        && !assume_yes
    {
        return Err(WalletCliError::ConfirmationRequired(format!(
            "{question}\nPass --yes to run state-changing commands in {mode_name}."
        )));
    }
    Ok(())
}

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

#[cfg(test)]
mod confirmation_gate_tests {
    use super::*;
    use wallet_cli_commands::build_repl_command;

    type Client = node_comm::node_traits::MockNodeInterface;

    // Grammar construction overflows small test stacks (see
    // wallet_cli_commands::run_with_large_stack), so run it on a large one.
    fn parse(line: &'static str) -> wallet_cli_commands::ManageableWalletCommand {
        wallet_cli_commands::run_with_large_stack(move || {
            wallet_cli_commands::parse_input::<node_comm::node_traits::MockNodeInterface>(
                line,
                &build_repl_command(false, true),
            )
            .expect("grammar parse must not fail")
            .expect("test lines parse to a command")
        })
    }

    #[test]
    fn state_changing_command_is_rejected_without_assume_yes() {
        let command = parse("address-send addr1 100");
        assert!(matches!(
            confirmation_gate::<Client>(&command, false, "exec mode"),
            Err(WalletCliError::ConfirmationRequired(_))
        ));
        confirmation_gate::<Client>(&command, true, "exec mode")
            .expect("assume_yes must let the command through");
    }

    #[test]
    fn read_only_command_never_needs_confirmation() {
        let command = parse("account-balance");
        confirmation_gate::<Client>(&command, false, "exec mode")
            .expect("read-only commands must not be gated");
    }
}

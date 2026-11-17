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

use clap::Command;
use tokio::sync::mpsc;
use wallet_cli_commands::{ConsoleCommand, ManageableWalletCommand};
use wallet_rpc_lib::types::NodeInterface;

use crate::{cli_event_loop::Event, errors::WalletCliError};

/// The grammar views (`help full`, `legacy`) are rendered by the shared
/// [`wallet_cli_commands::grammar_view_request`] entry point; see it for the
/// contract. This alias keeps the mode call sites short.
pub(crate) fn grammar_view_request(line: &str, repl_command: &Command) -> Option<String> {
    wallet_cli_commands::grammar_view_request(line, repl_command)
}

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

    res_rx.blocking_recv().map_err(|_recv_error| {
        WalletCliError::<N>::EventLoopShutdown("while waiting for the command result".to_owned())
    })?
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
    fn nested_spellings_hit_the_gate_too() {
        let command = parse("send addr1 100");
        assert!(matches!(
            confirmation_gate::<Client>(&command, false, "exec mode"),
            Err(WalletCliError::ConfirmationRequired(_))
        ));
        let command = parse("wallet purge-seed-phrase");
        assert!(matches!(
            confirmation_gate::<Client>(&command, false, "exec mode"),
            Err(WalletCliError::ConfirmationRequired(_))
        ));
    }

    #[test]
    fn read_only_command_never_needs_confirmation() {
        let command = parse("account-balance");
        confirmation_gate::<Client>(&command, false, "exec mode")
            .expect("read-only commands must not be gated");
    }

    #[test]
    fn help_full_renders_the_full_listing_without_parsing() {
        let repl = wallet_cli_commands::run_with_large_stack(|| {
            wallet_cli_commands::build_repl_command(false, true)
        });

        let listing =
            grammar_view_request("help full", &repl).expect("`help full` must render the listing");
        assert!(listing.contains("transaction"));
        assert!(listing.contains("transaction inspect"));
        // Both help views point at the legacy spelling listing.
        assert!(listing.contains("`legacy`"));
        // The legacy spellings stay out of the listing body itself.
        let listing_body = listing.split("Legacy flat spellings").next().expect("listing body");
        assert!(!listing_body.contains("address-new"));

        // The `legacy` request renders the grammar-filtered table.
        let table = grammar_view_request("legacy", &repl).expect("`legacy` must render the table");
        assert!(table.contains("wallet-create") && table.contains("wallet create"));

        // Regular help lines render as successful prints (exit 0 in the
        // non-interactive modes), unknown paths fall through to the parser.
        assert!(grammar_view_request("help", &repl).is_some());
        assert!(grammar_view_request("help wallet", &repl).is_some());
        assert!(grammar_view_request("help full extra", &repl).is_none());
        assert!(grammar_view_request("  help full  ", &repl).is_some());
        assert!(grammar_view_request("help address-new", &repl).is_some());

        // The cold grammar renders its own tree through the same path.
        let cold = wallet_cli_commands::run_with_large_stack(|| {
            wallet_cli_commands::build_repl_command(true, false)
        });
        let cold_listing =
            grammar_view_request("help full", &cold).expect("`help full` must render on cold");
        assert!(cold_listing.contains("challenge sign"));
        assert!(!cold_listing.contains("wallet create"));
        assert!(cold_listing.contains("`legacy`"));

        // The cold `legacy` table only lists the pairs that parse there.
        let cold_table =
            grammar_view_request("legacy", &cold).expect("`legacy` must render on cold");
        assert!(cold_table.contains("challenge-sign-plain"));
        assert!(!cold_table.contains("wallet-create"));

        // A quoted spelling is answered the way the parser tokenizes it.
        assert!(grammar_view_request("help \"full\"", &repl).is_some());
    }
}

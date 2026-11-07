// Copyright (c) 2024 RBB S.r.l
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

use clap::Command;
use tokio::sync::{mpsc, oneshot};
use wallet_cli_commands::{ConsoleCommand, build_repl_command, parse_input};
use wallet_rpc_lib::types::NodeInterface;

use crate::{
    cli_event_loop::Event, config::CliOutputFormat, console::ConsoleOutput, errors::WalletCliError,
};

#[derive(Debug)]
enum ExecOutput {
    Text(String),
    Json {
        text: Option<String>,
        value: serde_json::Value,
    },
    Nothing,
}

fn process_line<N: NodeInterface>(
    repl_command: &Command,
    event_tx: &mpsc::UnboundedSender<Event<N>>,
    line: &str,
    assume_yes: bool,
) -> Result<ExecOutput, WalletCliError<N>> {
    if let Some(listing) = super::grammar_view_request(line, repl_command) {
        return Ok(ExecOutput::Text(listing));
    }

    let command_opt = parse_input(line, repl_command)?;

    let command = match command_opt {
        Some(command) => command,
        None => return Ok(ExecOutput::Nothing),
    };

    super::confirmation_gate(&command, assume_yes, "exec mode")?;

    match super::run_command_blocking(event_tx, command)? {
        ConsoleCommand::Print(text) => Ok(ExecOutput::Text(text)),
        ConsoleCommand::Json { text, value } => Ok(ExecOutput::Json { text, value }),
        ConsoleCommand::Warn(message) => Ok(ExecOutput::Text(message)),
        ConsoleCommand::PaginatedPrint { header, body } => {
            let rendered = match (header.is_empty(), body.is_empty()) {
                (true, _) => body,
                (false, true) => header,
                (false, false) => format!("{header}\n{body}"),
            };
            Ok(ExecOutput::Text(rendered))
        }
        ConsoleCommand::SetStatus {
            status: _,
            print_message,
        } => Ok(ExecOutput::Text(print_message)),
        ConsoleCommand::ClearScreen
        | ConsoleCommand::PrintHistory
        | ConsoleCommand::ChoiceMenu(_)
        | ConsoleCommand::ClearHistory => Err(WalletCliError::InvalidInput(
            "Unsupported command in exec mode".to_owned(),
        )),
        ConsoleCommand::Exit => Ok(ExecOutput::Nothing),
    }
}

/// Runs one command line and renders its result. Errors propagate to the
/// caller, which maps them to a non-zero exit status.
///
/// `--output json` contract:
/// - migrated commands that emit structured data print their raw JSON value
///   (or `{"text": ..., "value": ...}` when they also carry a text line);
/// - commands that emit plain text print `{"output": "<text>"}`;
/// - failures are reported as plain text on standard error with a non-zero
///   exit status and no JSON envelope.
pub fn run<N: NodeInterface>(
    line: String,
    output_format: CliOutputFormat,
    assume_yes: bool,
    mut output: impl ConsoleOutput,
    event_tx: mpsc::UnboundedSender<Event<N>>,
    cold_wallet: bool,
    startup_command_futures: Vec<oneshot::Receiver<Result<ConsoleCommand, WalletCliError<N>>>>,
) -> Result<(), WalletCliError<N>> {
    for res_rx in startup_command_futures {
        let res = match res_rx.blocking_recv() {
            Ok(inner) => inner?,
            Err(_recv_error) => {
                return Err(WalletCliError::<N>::EventLoopShutdown(
                    "startup commands did not finish".to_owned(),
                ));
            }
        };
        // The startup command output is the wallet opening report; keep it off
        // standard output so the requested output format stays machine-parseable.
        // In json mode the startup result is folded into a single JSON object
        // (`{"text": ..., "value": ...}`) so stderr stays one parseable line,
        // matching the payload convention of the command output on stdout.
        match (output_format, res) {
            (CliOutputFormat::Json, ConsoleCommand::Json { text, value }) => {
                let envelope = json_payload(text, value);
                match serde_json::to_string(&envelope) {
                    Ok(rendered) => eprintln!("{rendered}"),
                    Err(err) => {
                        return Err(WalletCliError::<N>::SerdeJsonFormatError(err));
                    }
                }
            }
            (_, res) => {
                let line_out = to_startup_text(res);
                eprintln!("{line_out}");
            }
        }
    }

    // The REPL thread is sized for grammar construction, so build the
    // grammar directly instead of nesting another large-stack spawn.
    let repl_command = build_repl_command(cold_wallet, true);

    let result = process_line(&repl_command, &event_tx, &line, assume_yes)?;

    match (output_format, result) {
        (_, ExecOutput::Nothing) => {}
        (CliOutputFormat::Text, ExecOutput::Text(text)) => output.print_line(&text),
        (CliOutputFormat::Text, ExecOutput::Json { text, value }) => {
            output.print_line(&wallet_cli_commands::output::json_display_text(
                text, &value,
            ));
        }
        (CliOutputFormat::Json, ExecOutput::Text(text)) => output.print_line(
            &serde_json::to_string(&serde_json::json!({ "output": text }))
                .map_err(WalletCliError::SerdeJsonFormatError)?,
        ),
        (CliOutputFormat::Json, ExecOutput::Json { text, value }) => output.print_line(
            &serde_json::to_string(&json_payload(text, value))
                .map_err(WalletCliError::SerdeJsonFormatError)?,
        ),
    }

    Ok(())
}

/// The machine-readable payload for a `ConsoleCommand::Json`. A text-less
/// payload stays the raw value so existing `--output json` consumers that read
/// the command value directly keep working; the `text` key is added only when
/// the command carries human-readable text.
fn json_payload(text: Option<String>, value: serde_json::Value) -> serde_json::Value {
    match text {
        Some(text) => serde_json::json!({ "text": text, "value": value }),
        None => value,
    }
}

fn to_startup_text(command_output: ConsoleCommand) -> String {
    match command_output {
        ConsoleCommand::Print(text) => text,
        ConsoleCommand::Json { text, value } => {
            wallet_cli_commands::output::json_display_text(text, &value)
        }
        ConsoleCommand::Warn(message) => message,
        ConsoleCommand::PaginatedPrint { header, body } => {
            match (header.is_empty(), body.is_empty()) {
                (true, _) => body,
                (false, true) => header,
                (false, false) => format!("{header}\n{body}"),
            }
        }
        ConsoleCommand::SetStatus {
            status: _,
            print_message,
        } => print_message,
        ConsoleCommand::ClearScreen
        | ConsoleCommand::PrintHistory
        | ConsoleCommand::ChoiceMenu(_)
        | ConsoleCommand::ClearHistory
        | ConsoleCommand::Exit => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn parse_line(line: &'static str, cold: bool) -> Option<serde_json::Value> {
        // Grammar construction overflows the default 2 MiB test-thread stack,
        // so build it on a large-stack thread like the sibling test modules do.
        wallet_cli_commands::run_with_large_stack(move || {
            // Parse-only probe: build the grammar and reuse the shared parse path.
            let repl_command = build_repl_command(cold, true);
            parse_input::<node_comm::node_traits::MockNodeInterface>(line, &repl_command)
                .expect("grammar parse must not fail")
                .map(|_| serde_json::json!("parsed"))
        })
    }

    #[test]
    fn json_payload_keeps_textless_values_raw() {
        let value = serde_json::json!({ "peer_count": 3 });
        assert_eq!(json_payload(None, value.clone()), value);
        assert_eq!(
            json_payload(Some("peers".to_owned()), value.clone()),
            serde_json::json!({ "text": "peers", "value": value })
        );
    }

    #[test]
    fn exec_flag_parses_as_a_cli_arg() {
        let args: crate::config::WalletCliArgs =
            clap::Parser::parse_from(["wallet-cli", "--exec", "account create name"]);
        assert_eq!(args.cli_args().exec.as_deref(), Some("account create name"));
    }

    #[test]
    fn exec_grammar_accepts_a_cold_wallet_command() {
        // The cold-wallet grammar keeps the flat command names and drops the
        // hot-wallet groups, so pin the flat spelling here.
        assert_eq!(parse_line("wallet-info", true).unwrap(), "parsed");
    }

    // Grammar construction overflows the default 2 MiB test-thread stack.
    fn grammar() -> clap::Command {
        wallet_cli_commands::run_with_large_stack(|| build_repl_command(false, true))
    }

    // The view lines must answer without touching the event loop, so a dummy
    // channel stands in for it.
    fn exec_line(
        line: &str,
        grammar: &clap::Command,
        assume_yes: bool,
    ) -> Result<ExecOutput, WalletCliError<node_comm::node_traits::MockNodeInterface>> {
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
        process_line(grammar, &event_tx, line, assume_yes)
    }

    #[rstest]
    fn help_views_print_and_exit_zero_in_exec_mode(
        #[values((false, true), (true, false), (true, true))] (cold_wallet, mutable_wallet): (
            bool,
            bool,
        ),
    ) {
        // The shipped CLI builds (cold, true) in every mode; the cold variants
        // pin the contract for cold deployments too.
        let grammar = wallet_cli_commands::run_with_large_stack(move || {
            build_repl_command(cold_wallet, mutable_wallet)
        });
        // The cold grammars have no `wallet`/`address` groups, so their help
        // paths target the nested spellings they do carry.
        let lines: Vec<&str> = if cold_wallet {
            vec!["help full", "legacy", "help", "help challenge sign"]
        } else {
            vec!["help full", "legacy", "help", "help wallet", "help address standalone"]
        };
        for line in lines {
            match exec_line(line, &grammar, true) {
                Ok(ExecOutput::Text(text)) => {
                    assert!(!text.is_empty(), "`{line}` must render non-empty help text")
                }
                other => panic!("`{line}` must print in exec mode, got {other:?}"),
            }
        }
        // The views answer before the confirmation gate, so they print even
        // for callers that did not pass --yes.
        match exec_line("legacy", &grammar, false) {
            Ok(ExecOutput::Text(text)) => assert!(!text.is_empty()),
            other => panic!("`legacy` must print without --yes, got {other:?}"),
        }
    }

    #[test]
    fn unknown_help_paths_stay_parse_errors_in_exec_mode() {
        // The deliberate exit-code split: unknown paths fall through to the
        // parser and surface as failures, so scripts can tell them apart.
        let grammar = grammar();
        assert!(exec_line("help nonexistent-command", &grammar, true).is_err());
    }
}

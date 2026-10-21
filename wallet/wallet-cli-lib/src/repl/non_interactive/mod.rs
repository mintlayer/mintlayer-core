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

pub mod log;

use clap::Command;
use tokio::sync::{mpsc, oneshot};
use wallet_cli_commands::{ConsoleCommand, build_repl_command, parse_input};
use wallet_rpc_lib::types::NodeInterface;

use crate::{ConsoleInput, cli_event_loop::Event, console::ConsoleOutput, errors::WalletCliError};

#[derive(Debug)]
enum LineOutput {
    Print(String),
    Json {
        text: Option<String>,
        value: serde_json::Value,
    },
    Warn(String),
    None,
    Exit,
}

fn process_line<N: NodeInterface>(
    repl_command: &Command,
    event_tx: &mpsc::UnboundedSender<Event<N>>,
    line: &str,
    assume_yes: bool,
) -> Result<LineOutput, WalletCliError<N>> {
    let command_opt = parse_input(line, repl_command)?;

    let command = match command_opt {
        Some(command) => command,
        None => return Ok(LineOutput::None),
    };

    super::confirmation_gate(&command, assume_yes, "non-interactive mode")?;

    let command_output = super::run_command_blocking(event_tx, command)?;

    to_line_output(command_output)
}

fn to_line_output<N: NodeInterface>(
    command_output: ConsoleCommand,
) -> Result<LineOutput, WalletCliError<N>> {
    match command_output {
        ConsoleCommand::Print(text) => Ok(LineOutput::Print(text)),
        ConsoleCommand::Json { text, value } => Ok(LineOutput::Json { text, value }),
        ConsoleCommand::Warn(message) => Ok(LineOutput::Warn(message)),
        ConsoleCommand::PaginatedPrint { header, body } => {
            let rendered = match (header.is_empty(), body.is_empty()) {
                (true, _) => body,
                (false, true) => header,
                (false, false) => format!("{header}\n{body}"),
            };
            Ok(LineOutput::Print(rendered))
        }
        ConsoleCommand::SetStatus {
            status: _,
            print_message,
        } => Ok(LineOutput::Print(print_message)),
        ConsoleCommand::ClearScreen
        | ConsoleCommand::PrintHistory
        | ConsoleCommand::ChoiceMenu(_)
        | ConsoleCommand::ClearHistory => Err(WalletCliError::InvalidInput(
            "Unsupported command in non-interactive mode".to_owned(),
        )),
        ConsoleCommand::Exit => Ok(LineOutput::Exit),
    }
}

pub fn run<N: NodeInterface>(
    mut input: impl ConsoleInput,
    mut output: impl ConsoleOutput,
    event_tx: mpsc::UnboundedSender<Event<N>>,
    exit_on_error: bool,
    cold_wallet: bool,
    assume_yes: bool,
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
        let line_out = to_line_output(res);
        if let Some(value) = handle_response(line_out, &mut output, true) {
            return value;
        }
    }

    // The REPL thread is sized for grammar construction, so build the
    // grammar directly instead of nesting another large-stack spawn.
    let repl_command = build_repl_command(cold_wallet, true);

    while let Some(line) = input.read_line() {
        let res = process_line(&repl_command, &event_tx, &line, assume_yes);

        if let Some(value) = handle_response(res, &mut output, exit_on_error) {
            return value;
        }
    }

    Ok(())
}

fn handle_response<N: NodeInterface>(
    res: Result<LineOutput, WalletCliError<N>>,
    output: &mut impl ConsoleOutput,
    exit_on_error: bool,
) -> Option<Result<(), WalletCliError<N>>> {
    match res {
        Ok(LineOutput::Print(text)) => {
            output.print_line(&text);
        }
        Ok(LineOutput::Json { text, value }) => {
            let text = wallet_cli_commands::output::json_display_text(text, &value);
            output.print_line(&text);
        }
        Ok(LineOutput::Warn(message)) => {
            output.print_line(&message);
        }
        Ok(LineOutput::None) => {}
        Ok(LineOutput::Exit) => return Some(Ok(())),

        Err(err) => {
            if exit_on_error {
                return Some(Err(err));
            }

            output.print_error(err);
        }
    }
    None
}

#[cfg(test)]
mod rendering_tests {
    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct CapturingOutput {
        lines: Vec<String>,
    }

    impl ConsoleOutput for CapturingOutput {
        fn print_line(&mut self, line: &str) {
            self.lines.push(line.to_owned());
        }

        fn print_error<N: NodeInterface>(&mut self, _error: WalletCliError<N>) {
            unreachable!("errors are not exercised by these tests");
        }
    }

    fn render(command: ConsoleCommand) -> CapturingOutput {
        let line_output = to_line_output::<node_comm::node_traits::MockNodeInterface>(command)
            .expect("rendering must not fail");
        let mut output = CapturingOutput::default();
        let exit = handle_response::<node_comm::node_traits::MockNodeInterface>(
            Ok(line_output),
            &mut output,
            false,
        );
        assert!(exit.is_none(), "rendering a command output must not exit");
        output
    }

    #[test]
    fn json_payload_with_text_prints_the_text() {
        let output = render(ConsoleCommand::Json {
            text: Some("peer count: 3".to_owned()),
            value: json!(3),
        });
        assert_eq!(output.lines, ["peer count: 3"]);
    }

    #[test]
    fn json_payload_without_text_prints_the_pretty_value() {
        let output = render(ConsoleCommand::Json {
            text: None,
            value: json!({"key": "value"}),
        });
        assert_eq!(output.lines.len(), 1);
        assert_eq!(
            output.lines[0],
            serde_json::to_string_pretty(&json!({"key": "value"})).expect("static value")
        );
    }

    #[test]
    fn warn_is_printed_as_text() {
        let output = render(ConsoleCommand::Warn("heads up".to_owned()));
        assert_eq!(output.lines, ["heads up"]);
    }
}

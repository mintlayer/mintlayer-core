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
use wallet_cli_commands::{get_repl_command, parse_input, ConsoleCommand};
use wallet_rpc_lib::types::NodeInterface;

use crate::{cli_event_loop::Event, console::ConsoleOutput, errors::WalletCliError, ConsoleInput};

#[derive(Debug)]
enum LineOutput {
    Print(String),
    None,
    Exit,
}

fn process_line<N: NodeInterface>(
    repl_command: &Command,
    event_tx: &mpsc::UnboundedSender<Event<N>>,
    line: &str,
) -> Result<LineOutput, WalletCliError<N>> {
    let command_opt = parse_input(line, repl_command)?;

    let command = match command_opt {
        Some(command) => command,
        None => return Ok(LineOutput::None),
    };

    let command_output = super::run_command_blocking(event_tx, command)?;

    to_line_output(command_output, line)
}

fn to_line_output<N: NodeInterface>(
    command_output: ConsoleCommand,
    line: &str,
) -> Result<LineOutput, WalletCliError<N>> {
    match command_output {
        ConsoleCommand::Print(text) => Ok(LineOutput::Print(text)),
        ConsoleCommand::PaginatedPrint { header, body } => Ok(LineOutput::Print(header + &body)),
        ConsoleCommand::SetStatus {
            status: _,
            print_message,
        } => Ok(LineOutput::Print(print_message)),
        ConsoleCommand::ClearScreen
        | ConsoleCommand::PrintHistory
        | ConsoleCommand::ClearHistory => Err(WalletCliError::InvalidInput(format!(
            "Unsupported command in non-interactive mode: {}",
            line,
        ))),
        ConsoleCommand::Exit => Ok(LineOutput::Exit),
    }
}

pub fn run<N: NodeInterface>(
    mut input: impl ConsoleInput,
    mut output: impl ConsoleOutput,
    event_tx: mpsc::UnboundedSender<Event<N>>,
    exit_on_error: bool,
    cold_wallet: bool,
    startup_command_futures: Vec<oneshot::Receiver<Result<ConsoleCommand, WalletCliError<N>>>>,
) -> Result<(), WalletCliError<N>> {
    for res_rx in startup_command_futures {
        let res = res_rx.blocking_recv().expect("Channel must be open")?;
        let line_out = to_line_output(res, "startup command");
        if let Some(value) = handle_response(line_out, &mut output, true) {
            return value;
        }
    }

    let repl_command = get_repl_command(cold_wallet, true);

    while let Some(line) = input.read_line() {
        let res = process_line(&repl_command, &event_tx, &line);

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

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
use tokio::sync::mpsc;

use crate::{
    cli_event_loop::Event, cli_println, commands::ConsoleCommand, console::ConsoleContext,
    errors::WalletCliError,
};

use super::{get_repl_command, parse_input};

enum LineOutput {
    Print(String),
    None,
    Exit,
}

fn process_line(
    repl_command: &Command,
    event_tx: &mpsc::UnboundedSender<Event>,
    line: &str,
) -> Result<LineOutput, WalletCliError> {
    let command_opt = parse_input(line, repl_command)?;

    let command = match command_opt {
        Some(command) => command,
        None => return Ok(LineOutput::None),
    };

    let command_output = super::run_command_blocking(event_tx, command)?;

    match command_output {
        ConsoleCommand::Print(text) => Ok(LineOutput::Print(text)),
        ConsoleCommand::ClearScreen
        | ConsoleCommand::PrintHistory
        | ConsoleCommand::ClearHistory => Err(WalletCliError::InvalidInput(format!(
            "Unsupported command in non-interactive mode: {}",
            line,
        ))),
        ConsoleCommand::Exit => Ok(LineOutput::Exit),
    }
}

pub fn run(
    lines: impl Iterator<Item = String>,
    output: &ConsoleContext,
    event_tx: mpsc::UnboundedSender<Event>,
    exit_on_error: bool,
) -> Result<(), WalletCliError> {
    let repl_command = get_repl_command();

    for line in lines {
        let res = process_line(&repl_command, &event_tx, &line);

        match res {
            Ok(LineOutput::Print(text)) => {
                cli_println!(output, "{}", text);
            }
            Ok(LineOutput::None) => {}
            Ok(LineOutput::Exit) => return Ok(()),

            Err(err) => {
                if exit_on_error {
                    return Err(err);
                }

                cli_println!(output, "{}", err);
            }
        }
    }

    Ok(())
}

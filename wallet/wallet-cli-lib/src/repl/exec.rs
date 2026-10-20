// Copyright (c) 2024 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// One-shot mode: run a single wallet command from the command line and exit.

use clap::Command;
use tokio::sync::{mpsc, oneshot};
use wallet_cli_commands::{ConsoleCommand, build_repl_command, parse_input};
use wallet_rpc_lib::types::NodeInterface;

use crate::{
    cli_event_loop::Event, config::CliOutputFormat, console::ConsoleOutput, errors::WalletCliError,
};

enum ExecOutput {
    Text(String),
    Json(serde_json::Value),
    Nothing,
}

fn process_line<N: NodeInterface>(
    repl_command: &Command,
    event_tx: &mpsc::UnboundedSender<Event<N>>,
    line: &str,
    assume_yes: bool,
) -> Result<ExecOutput, WalletCliError<N>> {
    let command_opt = parse_input(line, repl_command)?;

    let command = match command_opt {
        Some(command) => command,
        None => return Ok(ExecOutput::Nothing),
    };

    super::confirmation_gate(&command, assume_yes, "exec mode")?;

    match super::run_command_blocking(event_tx, command)? {
        ConsoleCommand::Print(text) => Ok(ExecOutput::Text(text)),
        ConsoleCommand::Json { text, value } => Ok(match text {
            Some(text) => ExecOutput::Json(serde_json::json!({ "text": text, "value": value })),
            None => ExecOutput::Json(value),
        }),
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
        | ConsoleCommand::ClearHistory => Err(WalletCliError::InvalidInput(format!(
            "Unsupported command in exec mode: {line}",
        ))),
        ConsoleCommand::Exit => Ok(ExecOutput::Nothing),
    }
}

/// Runs one command line and renders its result. Errors propagate to the
/// caller, which maps them to a non-zero exit status.
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
        let res = res_rx.blocking_recv().expect("Channel must be open")?;
        // The startup command output is the wallet opening report; render it
        // as text regardless of the requested format so the JSON stream on
        // standard output carries only the requested command's result.
        let line_out = to_startup_text(res);
        output.print_line(&line_out);
    }

    // The REPL thread is sized for grammar construction, so build the
    // grammar directly instead of nesting another large-stack spawn.
    let repl_command = build_repl_command(cold_wallet, true);

    let result = process_line(&repl_command, &event_tx, &line, assume_yes)?;

    match (output_format, result) {
        (_, ExecOutput::Nothing) => {}
        (CliOutputFormat::Text, ExecOutput::Text(text)) => output.print_line(&text),
        (CliOutputFormat::Text, ExecOutput::Json(value)) => {
            output.print_line(&wallet_cli_commands::output::json_display_text(
                None, &value,
            ));
        }
        (CliOutputFormat::Json, ExecOutput::Text(text)) => output.print_line(
            &serde_json::to_string(&serde_json::json!({ "output": text }))
                .map_err(WalletCliError::SerdeJsonFormatError)?,
        ),
        (CliOutputFormat::Json, ExecOutput::Json(value)) => output.print_line(
            &serde_json::to_string(&value).map_err(WalletCliError::SerdeJsonFormatError)?,
        ),
    }

    Ok(())
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

    fn parse_line(line: &str, cold: bool) -> Option<serde_json::Value> {
        // Parse-only probe: build the grammar and reuse the shared parse path.
        let repl_command = build_repl_command(cold, true);
        parse_input::<node_comm::node_traits::MockNodeInterface>(line, &repl_command)
            .expect("grammar parse must not fail")
            .map(|_| serde_json::json!("parsed"))
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
}

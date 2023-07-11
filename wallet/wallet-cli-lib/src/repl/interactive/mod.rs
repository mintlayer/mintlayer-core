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

mod key_bindings;
pub mod log;
mod wallet_completions;
mod wallet_prompt;

use std::path::PathBuf;

use clap::Command;
use reedline::{
    default_emacs_keybindings, default_vi_insert_keybindings, default_vi_normal_keybindings,
    ColumnarMenu, DefaultValidator, EditMode, Emacs, FileBackedHistory, ListMenu, Reedline,
    ReedlineMenu, Signal, Vi,
};
use tokio::sync::{mpsc, oneshot};

use crate::{
    cli_event_loop::Event, commands::ConsoleCommand, console::ConsoleOutput,
    errors::WalletCliError, repl::interactive::key_bindings::add_menu_keybindings,
};

use super::{get_repl_command, parse_input};

const HISTORY_MAX_LINES: usize = 1000;

const HISTORY_MENU_NAME: &str = "history_menu";
const COMPLETION_MENU_NAME: &str = "completion_menu";

fn create_line_editor(
    printer: reedline::ExternalPrinter<String>,
    repl_command: super::Command,
    history_file: Option<PathBuf>,
    vi_mode: bool,
) -> Result<Reedline, WalletCliError> {
    let commands = repl_command
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .chain(std::iter::once("help".to_owned()))
        .collect::<Vec<_>>();

    let completer = Box::new(wallet_completions::WalletCompletions::new(commands));

    let mut line_editor = Reedline::create()
        .with_external_printer(printer)
        .with_completer(completer)
        .with_quick_completions(false)
        .with_partial_completions(true)
        .with_validator(Box::new(DefaultValidator))
        .with_ansi_colors(true);

    if let Some(file_name) = history_file {
        let history = Box::new(
            FileBackedHistory::with_file(HISTORY_MAX_LINES, file_name.clone())
                .map_err(|e| WalletCliError::FileError(file_name, e))?,
        );
        line_editor = line_editor.with_history(history);
    }

    // Adding default menus for the compiled reedline
    line_editor = line_editor
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(
            ColumnarMenu::default().with_name(COMPLETION_MENU_NAME),
        )))
        .with_menu(ReedlineMenu::HistoryMenu(Box::new(
            ListMenu::default().with_name(HISTORY_MENU_NAME),
        )));

    let edit_mode: Box<dyn EditMode> = if vi_mode {
        let mut normal_keybindings = default_vi_normal_keybindings();
        let mut insert_keybindings = default_vi_insert_keybindings();

        add_menu_keybindings(&mut normal_keybindings);
        add_menu_keybindings(&mut insert_keybindings);

        Box::new(Vi::new(insert_keybindings, normal_keybindings))
    } else {
        let mut keybindings = default_emacs_keybindings();
        add_menu_keybindings(&mut keybindings);

        Box::new(Emacs::new(keybindings))
    };

    line_editor = line_editor.with_edit_mode(edit_mode);

    Ok(line_editor)
}

fn process_line(
    repl_command: &Command,
    event_tx: &mpsc::UnboundedSender<Event>,
    sig: reedline::Signal,
) -> Result<Option<ConsoleCommand>, WalletCliError> {
    let line = match sig {
        Signal::Success(line) => line,
        Signal::CtrlC => {
            // Prompt has been cleared and should start on the next line
            return Ok(None);
        }
        Signal::CtrlD => {
            return Ok(Some(ConsoleCommand::Exit));
        }
    };

    let command_opt = parse_input(&line, repl_command)?;

    let command = match command_opt {
        Some(command) => command,
        None => return Ok(None),
    };

    super::run_command_blocking(event_tx, command).map(Option::Some)
}

pub fn run(
    mut console: impl ConsoleOutput,
    event_tx: mpsc::UnboundedSender<Event>,
    exit_on_error: bool,
    logger: log::InteractiveLogger,
    history_file: Option<PathBuf>,
    vi_mode: bool,
    startup_command_futures: Vec<oneshot::Receiver<Result<ConsoleCommand, WalletCliError>>>,
) -> Result<(), WalletCliError> {
    let repl_command = get_repl_command();

    let mut line_editor =
        create_line_editor(logger.printer().clone(), repl_command.clone(), history_file, vi_mode)?;

    let mut prompt = wallet_prompt::WalletPrompt::new();

    // first wait for the results of any startup command before processing the rest
    for res_rx in startup_command_futures {
        let res = res_rx.blocking_recv().expect("Channel must be open");
        if let Some(value) =
            handle_response(res.map(Some), &mut console, &mut prompt, &mut line_editor, true)
        {
            return value;
        }
    }

    console.print_line("Use 'help' to see all available commands.");
    console.print_line("Use 'exit' or Ctrl-D to quit.");

    loop {
        logger.set_print_directly(false);
        let sig = line_editor.read_line(&prompt).expect("Should not fail normally");
        logger.set_print_directly(true);

        let res = process_line(&repl_command, &event_tx, sig);

        if let Some(value) =
            handle_response(res, &mut console, &mut prompt, &mut line_editor, exit_on_error)
        {
            return value;
        }
    }
}

fn handle_response(
    res: Result<Option<ConsoleCommand>, WalletCliError>,
    console: &mut impl ConsoleOutput,
    prompt: &mut wallet_prompt::WalletPrompt,
    line_editor: &mut Reedline,
    exit_on_error: bool,
) -> Option<Result<(), WalletCliError>> {
    match res {
        Ok(Some(ConsoleCommand::Print(text))) => {
            console.print_line(&text);
        }
        Ok(Some(ConsoleCommand::SetStatus { status, print_message })) => {
            prompt.set_status(status);
            console.print_line(&print_message);
        }
        Ok(Some(ConsoleCommand::ClearScreen)) => {
            line_editor.clear_scrollback().expect("Should not fail normally");
        }
        Ok(Some(ConsoleCommand::ClearHistory)) => {
            line_editor.history_mut().clear().expect("Should not fail normally");
        }
        Ok(Some(ConsoleCommand::PrintHistory)) => {
            line_editor.print_history().expect("Should not fail normally");
        }
        Ok(Some(ConsoleCommand::Exit)) => return Some(Ok(())),

        Ok(None) => {}

        Err(err) => {
            if exit_on_error {
                return Some(Err(err));
            }
            console.print_error(err);
        }
    }
    None
}

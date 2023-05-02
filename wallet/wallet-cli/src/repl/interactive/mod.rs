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

use std::path::Path;

use reedline::{
    default_emacs_keybindings, default_vi_insert_keybindings, default_vi_normal_keybindings,
    ColumnarMenu, DefaultValidator, EditMode, Emacs, FileBackedHistory, ListMenu, Reedline,
    ReedlineMenu, Signal, Vi,
};
use tokio::sync::mpsc;

use crate::{
    cli_event_loop::Event, cli_println, commands::ConsoleCommand, console::ConsoleContext,
    errors::WalletCliError, repl::interactive::key_bindings::add_menu_keybindings,
};

use super::{get_repl_command, parse_input};

const HISTORY_FILE_NAME: &str = "history.txt";
const HISTORY_MAX_LINES: usize = 1000;

const HISTORY_MENU_NAME: &str = "history_menu";
const COMPLETION_MENU_NAME: &str = "completion_menu";

fn create_line_editor(
    printer: reedline::ExternalPrinter<String>,
    repl_command: super::Command,
    output: &ConsoleContext,
    data_dir: &Path,
    vi_mode: bool,
) -> Result<Reedline, WalletCliError> {
    cli_println!(output, "Use 'help' to see all available commands.");
    cli_println!(output, "Use 'exit' or Ctrl-D to quit.");

    let history_file_path = data_dir.join(HISTORY_FILE_NAME);
    let history = Box::new(
        FileBackedHistory::with_file(HISTORY_MAX_LINES, history_file_path.clone())
            .map_err(|e| WalletCliError::HistoryFileError(history_file_path, e))?,
    );

    let commands = repl_command
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .chain(std::iter::once("help".to_owned()))
        .collect::<Vec<_>>();

    let completer = Box::new(wallet_completions::WalletCompletions::new(commands));

    let mut line_editor = Reedline::create()
        .with_external_printer(printer)
        .with_history(history)
        .with_completer(completer)
        .with_quick_completions(false)
        .with_partial_completions(true)
        .with_validator(Box::new(DefaultValidator))
        .with_ansi_colors(true);

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

pub fn run(
    output: &ConsoleContext,
    event_tx: mpsc::UnboundedSender<Event>,
    printer: reedline::ExternalPrinter<String>,
    data_dir: &Path,
    vi_mode: bool,
) -> Result<(), WalletCliError> {
    let repl_command = get_repl_command();
    let mut line_editor =
        create_line_editor(printer, repl_command.clone(), output, data_dir, vi_mode)?;

    let prompt = wallet_prompt::WalletPrompt::new();

    loop {
        let sig = line_editor.read_line(&prompt);

        match sig {
            Ok(Signal::Success(line)) => {
                let res = parse_input(&line, &repl_command);
                match res {
                    Ok(Some(command)) => {
                        let res = super::run_command_blocking(&event_tx, command);

                        match res {
                            Ok(cmd) => match cmd {
                                ConsoleCommand::Print(text) => {
                                    cli_println!(output, "{}", text);
                                }
                                ConsoleCommand::ClearScreen => {
                                    line_editor
                                        .clear_scrollback()
                                        .expect("Should not fail normally");
                                }
                                ConsoleCommand::PrintHistory => {
                                    line_editor.print_history().expect("Should not fail normally");
                                }
                                ConsoleCommand::ClearHistory => {
                                    line_editor
                                        .history_mut()
                                        .clear()
                                        .expect("Should not fail normally");
                                }
                                ConsoleCommand::Exit => return Ok(()),
                            },
                            Err(e) => {
                                cli_println!(output, "{}", e);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(WalletCliError::InvalidCommandInput(e)) => {
                        // Print help and parse errors using styles
                        e.print().expect("Should not fail normally");
                    }
                    Err(e) => {
                        cli_println!(output, "{}", e);
                    }
                }
            }
            Ok(Signal::CtrlC) => {
                // Prompt has been cleared and should start on the next line
            }
            Ok(Signal::CtrlD) => {
                return Ok(());
            }
            Err(err) => {
                cli_println!(output, "Error: {err:?}");
            }
        }
    }
}

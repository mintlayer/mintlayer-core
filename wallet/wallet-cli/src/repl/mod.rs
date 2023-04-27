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

mod wallet_completions;
mod wallet_prompt;

use std::path::Path;

use clap::{Command, FromArgMatches, Subcommand};
use reedline::{
    default_emacs_keybindings, default_vi_insert_keybindings, default_vi_normal_keybindings,
    ColumnarMenu, DefaultValidator, EditCommand, EditMode, Emacs, FileBackedHistory, KeyCode,
    KeyModifiers, Keybindings, ListMenu, Reedline, ReedlineEvent, ReedlineMenu, Signal, Vi,
};
use tokio::sync::mpsc;

use crate::{
    cli_event_loop::Event,
    cli_println,
    commands::{ConsoleCommand, WalletCommand},
    console::ConsoleContext,
    errors::WalletCliError,
    repl::{wallet_completions::WalletCompletions, wallet_prompt::WalletPrompt},
};

const HISTORY_FILE_NAME: &str = "history.txt";
const HISTORY_MAX_LINES: usize = 1000;

// Strip out usage
const MAIN_HELP_TEMPLATE: &str = "\
    {all-args}
";

// Strip out name/version
const COMMAND_HELP_TEMPLATE: &str = "\
    {about-with-newline}\n\
    {usage-heading}\n    {usage}\n\
    \n\
    {all-args}{after-help}\
";

pub fn get_repl_command() -> Command {
    let repl_command = Command::new("repl")
        .multicall(true)
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand_value_name("Command")
        .subcommand_help_heading("Commands")
        .help_template(MAIN_HELP_TEMPLATE);

    // Add commands from generated by clap-derive
    let mut repl_command = WalletCommand::augment_subcommands(repl_command);

    // Customize the help template for all commands to make it more REPL friendly
    for subcommand in repl_command.get_subcommands_mut() {
        *subcommand = subcommand.clone().help_template(COMMAND_HELP_TEMPLATE);
    }

    repl_command
}

/// Try to parse REPL input string as a [WalletCommands]
fn parse_input(line: &str, repl_command: &Command) -> Result<WalletCommand, WalletCliError> {
    // Split arguments as a normal shell would do
    let args = shlex::split(line).ok_or(WalletCliError::InvalidQuoting)?;
    let mut matches = repl_command
        .clone()
        .try_get_matches_from(args)
        .map_err(WalletCliError::InvalidCommandInput)?;
    let command = WalletCommand::from_arg_matches_mut(&mut matches)
        .map_err(WalletCliError::InvalidCommandInput)?;
    Ok(command)
}

pub fn create_line_editor(
    printer: reedline::ExternalPrinter<String>,
    repl_command: Command,
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

    let completer = Box::new(WalletCompletions::new(commands));

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
            ColumnarMenu::default().with_name("completion_menu"),
        )))
        .with_menu(ReedlineMenu::HistoryMenu(Box::new(
            ListMenu::default().with_name("history_menu"),
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
    mut line_editor: Reedline,
    repl_command: Command,
    event_tx: mpsc::UnboundedSender<Event>,
    output: &ConsoleContext,
) {
    let prompt = WalletPrompt::new();

    loop {
        let sig = line_editor.read_line(&prompt);

        match sig {
            Ok(Signal::Success(line)) => {
                let line = line.trim();
                if !line.is_empty() {
                    let res = parse_input(line, &repl_command);
                    match res {
                        Ok(command) => {
                            let (res_tx, res_rx) = tokio::sync::oneshot::channel();
                            event_tx.send(Event::HandleCommand { command, res_tx }).expect("");
                            let res = res_rx.blocking_recv().expect("");

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
                                        line_editor
                                            .print_history()
                                            .expect("Should not fail normally");
                                    }
                                    ConsoleCommand::ClearHistory => {
                                        line_editor
                                            .history_mut()
                                            .clear()
                                            .expect("Should not fail normally");
                                    }
                                    ConsoleCommand::Exit => return,
                                },
                                Err(e) => {
                                    cli_println!(output, "{}", e);
                                }
                            }
                        }
                        Err(WalletCliError::InvalidCommandInput(e)) => {
                            // Print help and parse errors using styles
                            e.print().expect("Should not fail normally");
                        }
                        Err(e) => {
                            cli_println!(output, "{}", e);
                        }
                    }
                }
            }
            Ok(Signal::CtrlC) => {
                // Prompt has been cleared and should start on the next line
            }
            Ok(Signal::CtrlD) => {
                return;
            }
            Err(err) => {
                cli_println!(output, "Error: {err:?}");
            }
        }
    }
}

fn add_menu_keybindings(keybindings: &mut Keybindings) {
    keybindings.add_binding(
        KeyModifiers::CONTROL,
        KeyCode::Char('x'),
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("history_menu".to_string()),
            ReedlineEvent::MenuPageNext,
        ]),
    );

    keybindings.add_binding(
        KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        KeyCode::Char('x'),
        ReedlineEvent::MenuPagePrevious,
    );

    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::Edit(vec![EditCommand::Complete]),
        ]),
    );

    keybindings.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::MenuPrevious,
    );
}

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
use itertools::Itertools;
use reedline::{
    default_emacs_keybindings, default_vi_insert_keybindings, default_vi_normal_keybindings,
    ColumnarMenu, DefaultPrompt, DefaultValidator, EditMode, Emacs, FileBackedHistory, History,
    ListMenu, MenuBuilder, Reedline, ReedlineMenu, Signal, Vi,
};

use tokio::sync::{mpsc, oneshot};
use utils::once_destructor::OnceDestructor;
use wallet_cli_commands::{
    get_repl_command, parse_input, ChoiceMenu, ConsoleCommand, ManageableWalletCommand,
};
use wallet_rpc_lib::types::NodeInterface;

use crate::{
    cli_event_loop::Event, console::ConsoleOutput, errors::WalletCliError,
    repl::interactive::key_bindings::add_menu_keybindings,
};

const HISTORY_MAX_LINES: usize = 1000;

const HISTORY_MENU_NAME: &str = "history_menu";
const COMPLETION_MENU_NAME: &str = "completion_menu";

fn create_line_editor(
    printer: reedline::ExternalPrinter<String>,
    commands: Vec<String>,
    history: Option<Box<dyn History>>,
    vi_mode: bool,
) -> Reedline {
    let completer = Box::new(wallet_completions::WalletCompletions::new(commands));

    let mut line_editor = Reedline::create()
        .with_external_printer(printer)
        .with_completer(completer)
        .with_quick_completions(false)
        .with_partial_completions(true)
        .with_validator(Box::new(DefaultValidator))
        .with_ansi_colors(true);

    if let Some(history) = history {
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

    line_editor.with_edit_mode(edit_mode)
}

fn process_line<N: NodeInterface>(
    repl_command: &Command,
    event_tx: &mpsc::UnboundedSender<Event<N>>,
    sig: reedline::Signal,
) -> Result<Option<ConsoleCommand>, WalletCliError<N>> {
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

#[allow(clippy::too_many_arguments)]
pub fn run<N: NodeInterface>(
    mut console: impl ConsoleOutput,
    event_tx: mpsc::UnboundedSender<Event<N>>,
    exit_on_error: bool,
    logger: log::InteractiveLogger,
    history_file: Option<PathBuf>,
    vi_mode: bool,
    startup_command_futures: Vec<oneshot::Receiver<Result<ConsoleCommand, WalletCliError<N>>>>,
    cold_wallet: bool,
) -> Result<(), WalletCliError<N>> {
    let repl_command = get_repl_command(cold_wallet, true);

    let commands = repl_command
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
        .map(|command| command.get_name().to_owned())
        .collect::<Vec<_>>();

    let history = if let Some(file_name) = history_file {
        let h: Box<dyn History> = Box::new(
            FileBackedHistory::with_file(HISTORY_MAX_LINES, file_name.clone())
                .map_err(|e| WalletCliError::FileError(file_name, e.to_string()))?,
        );
        Some(h)
    } else {
        None
    };

    let mut line_editor = create_line_editor(logger.printer().clone(), commands, history, vi_mode);

    let mut prompt = wallet_prompt::WalletPrompt::new();

    // first wait for the results of any startup command before processing the rest
    for res_rx in startup_command_futures {
        let res = res_rx.blocking_recv().expect("Channel must be open");
        match handle_response(
            res.map(Some),
            &mut console,
            &mut prompt,
            &mut line_editor,
            &logger,
            vi_mode,
            true,
        ) {
            CommandResponse::Exit => return Ok(()),
            CommandResponse::Error(err) => return Err(err),
            CommandResponse::Command(_) => return Err(WalletCliError::UnexpectedInteraction),
            CommandResponse::Continue => {}
        }
    }

    console.print_line("Use 'help' to see all available commands.");
    console.print_line("Use 'help <command>' to learn more about the parameters of the command.");
    console.print_line("Press TAB on your keyboard to auto-complete any command you write.");
    console.print_line("Use 'exit' or Ctrl-D to quit.");

    let mut cmd = None;
    loop {
        let res = if let Some(command) = cmd.take() {
            super::run_command_blocking(&event_tx, command).map(Option::Some)
        } else {
            logger.set_print_directly(false);
            let sig = line_editor.read_line(&prompt).expect("Should not fail normally");
            logger.set_print_directly(true);

            process_line(&repl_command, &event_tx, sig)
        };

        match handle_response(
            res,
            &mut console,
            &mut prompt,
            &mut line_editor,
            &logger,
            vi_mode,
            exit_on_error,
        ) {
            CommandResponse::Exit => return Ok(()),
            CommandResponse::Error(err) => return Err(err),
            CommandResponse::Continue => {}
            CommandResponse::Command(command) => cmd = Some(*command),
        }
    }
}

enum CommandResponse<N: NodeInterface> {
    Exit,
    Continue,
    Error(WalletCliError<N>),
    Command(Box<ManageableWalletCommand>),
}

fn handle_response<N: NodeInterface>(
    res: Result<Option<ConsoleCommand>, WalletCliError<N>>,
    console: &mut impl ConsoleOutput,
    prompt: &mut wallet_prompt::WalletPrompt,
    line_editor: &mut Reedline,
    logger: &log::InteractiveLogger,
    vi_mode: bool,
    exit_on_error: bool,
) -> CommandResponse<N> {
    match res {
        Ok(Some(ConsoleCommand::Print(text))) => {
            console.print_line(&text);
        }
        Ok(Some(ConsoleCommand::PaginatedPrint { header, body })) => {
            paginate_output(header, body, line_editor, console, logger)
                .expect("Should not fail normally");
        }
        Ok(Some(ConsoleCommand::SetStatus {
            status,
            print_message,
        })) => {
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
        Ok(Some(ConsoleCommand::Exit)) => return CommandResponse::Exit,

        Ok(Some(ConsoleCommand::ChoiceMenu(choice))) => {
            let line_editor_helper =
                create_line_editor(logger.printer().clone(), vec![], None, vi_mode);
            let cmd = handle_choice_menu(choice.as_ref(), line_editor_helper);
            if let Some(cmd) = cmd {
                return CommandResponse::Command(Box::new(cmd));
            }
        }

        Ok(None) => {}

        Err(err) => {
            if exit_on_error {
                return CommandResponse::Error(err);
            }
            console.print_error(err);
        }
    }

    CommandResponse::Continue
}

fn handle_choice_menu(
    choice_menu: &dyn ChoiceMenu,
    mut line_editor: Reedline,
) -> Option<ManageableWalletCommand> {
    let prompt = DefaultPrompt::new(
        reedline::DefaultPromptSegment::Empty,
        reedline::DefaultPromptSegment::Empty,
    );

    let choice_list = choice_menu.choice_list();
    let exit_index = choice_list.len();
    loop {
        println!("{}", choice_menu.header());
        for (idx, choice) in choice_list.iter().enumerate() {
            println!("{idx}: {choice}");
        }
        println!("{exit_index}: Exit");

        match line_editor.read_line(&prompt).expect("Should not fail normally") {
            Signal::Success(input) => {
                let input = input.trim();

                if input.eq_ignore_ascii_case("Exit") {
                    return None;
                }

                match input.parse() {
                    Ok(index) if index == exit_index => return None,
                    Ok(index) if index < exit_index => {
                        if let Some(cmd) = choice_menu.choose(index) {
                            println!("You selected: {}", choice_list[index]);
                            return Some(cmd);
                        }
                    }
                    _ => {}
                };

                println!("Invalid choice! Please select a valid option.");
            }
            Signal::CtrlD | Signal::CtrlC => {
                return None;
            }
        }
    }
}

fn paginate_output(
    header: String,
    body: String,
    line_editor: &mut Reedline,
    console: &mut impl ConsoleOutput,
    logger: &log::InteractiveLogger,
) -> std::io::Result<()> {
    let mut current_index = 0;

    // Disable the direct logging, because:
    // a) we don't want any log output to appear in the paginated output;
    // b) the log output will appear broken in the raw mode anyway (which we switch the terminal
    // into inside `read_command`).
    // Note: the logs will be collected inside `reedline::ExternalPrinter` and printed
    // by `Readline::read_line` later.
    logger.set_print_directly(false);
    // Enter the alternate screen, to preserve the existing contents of the terminal.
    // Note: this call will basically send a certain ANSI code to the specified stream and then
    // flush the stream. It shouldn't matter whether we use stdout or stderr here.
    crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    // Undo all of the above on function exit.
    let _cleanup = OnceDestructor::new(|| {
        // Note: we can't do anything about the possible error here. Panicking is probably
        // better than ignoring it, because the UI will likely be broken anyway
        // (though it's not clear under which conditions such an error can occur).
        crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)
            .expect("failure when leaving alternate terminal screen");
        logger.set_print_directly(true);
    });

    let (mut page_rows, mut offsets) = compute_page_line_offsets(&body);
    let mut last_batch = offsets.len() - 1;

    loop {
        line_editor.clear_screen()?;

        let end_batch = std::cmp::min(current_index + page_rows, last_batch);
        let start = offsets[current_index];
        let end = offsets[end_batch];
        console.print_line(&header);
        console.print_line(body.get(start..end).expect("safe point"));

        let commands = match (current_index, end_batch) {
            (0, end) if end == last_batch => "Press 'q' to quit",
            (0, _) => "Press 'j' for next, 'q' to quit",
            (_, end) if end == last_batch => "Press 'k' for previous, 'q' to quit",
            _ => "Press 'j' for next, 'k' for previous, 'q' to quit",
        };
        console.print_line(commands);

        match read_command(current_index, last_batch, end_batch)? {
            PagginationCommand::Exit => break,
            PagginationCommand::Next => {
                current_index += 1;
            }
            PagginationCommand::Previous => {
                current_index -= 1;
            }
            PagginationCommand::TerminalResize => {
                (page_rows, offsets) = compute_page_line_offsets(&body);
                last_batch = offsets.len() - 1;
                current_index = std::cmp::min(current_index, last_batch - page_rows);
            }
        }
    }

    line_editor.clear_screen()
}

fn compute_page_line_offsets(body: &str) -> (usize, Vec<usize>) {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let cols = cols as usize;

    // make room for the header and prompt
    let page_rows = (rows - 4) as usize;

    let position_offsets = (0..1) // prepend 0 as starting position
        .chain(body.char_indices().peekable().batching(|it| {
            // if no more characters exit
            it.peek()?;

            // advance the iterator to the next new line or at least cols characters
            let _skip = it.take(cols).find(|(_, c)| *c == '\n');

            match it.peek() {
                Some((idx, _)) => Some(*idx),
                None => Some(body.len()),
            }
        }))
        .collect_vec();
    (page_rows, position_offsets)
}

enum PagginationCommand {
    Exit,
    Next,
    Previous,
    TerminalResize,
}

fn read_command(
    current_index: usize,
    last_batch: usize,
    end_batch: usize,
) -> Result<PagginationCommand, std::io::Error> {
    // TODO: maybe enable raw mode only once per pagination
    crossterm::terminal::enable_raw_mode()?;
    let _cleanup = OnceDestructor::new(|| {
        // Same as in `paginate_output`, we can't do much about the possible error, so we just panic.
        crossterm::terminal::disable_raw_mode().expect("failure when disabling raw terminal mode")
    });

    loop {
        let event = crossterm::event::read()?;

        match event {
            crossterm::event::Event::Key(key_event) => {
                match key_event.code {
                    reedline::KeyCode::Char('j') | reedline::KeyCode::Down
                        if end_batch < last_batch =>
                    {
                        return Ok(PagginationCommand::Next)
                    }
                    reedline::KeyCode::Char('k') | reedline::KeyCode::Up if current_index > 0 => {
                        return Ok(PagginationCommand::Previous)
                    }
                    reedline::KeyCode::Char('q') | reedline::KeyCode::Esc => {
                        return Ok(PagginationCommand::Exit);
                    }
                    _ => {} // Ignore other keys
                }
            }
            crossterm::event::Event::Resize(_, _) => return Ok(PagginationCommand::TerminalResize),
            _ => {}
        }
    }
}

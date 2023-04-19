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

use std::borrow::Cow;

use reedline::{
    default_emacs_keybindings, default_vi_insert_keybindings, default_vi_normal_keybindings,
    ColumnarMenu, DefaultCompleter, DefaultHinter, DefaultValidator, EditMode, Emacs,
    ExampleHighlighter, FileBackedHistory, ListMenu, Prompt, PromptEditMode, PromptHistorySearch,
    PromptHistorySearchStatus, Reedline, ReedlineMenu, Signal, Vi,
};

use crate::{cli_println, WalletCliError};

const MAX_HISTORY: usize = 1000;

// For custom prompt, implement the Prompt trait
//
// This example displays the number of keystrokes
// or rather increments each time the prompt is rendered.
#[derive(Clone)]
pub struct CustomPrompt {}

impl Prompt for CustomPrompt {
    fn render_prompt_left(&self) -> Cow<str> {
        Cow::Borrowed("Wallet")
    }

    fn render_prompt_right(&self) -> Cow<str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<str> {
        Cow::Borrowed("> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

pub fn start_cli_repl() -> Result<(), WalletCliError> {
    cli_println!("Ctrl-D to quit");
    // quick command like parameter handling
    let vi_mode = matches!(std::env::args().nth(1), Some(x) if x == "--vi");

    // TODO(PR): Keep history in the wallets dir
    let history =
        Box::new(FileBackedHistory::with_file(MAX_HISTORY, "history.txt".into()).unwrap());

    let commands = vec!["clear".into(), "exit".into(), "history".into()];

    let completer = Box::new(DefaultCompleter::new_with_wordlen(commands.clone(), 0));

    let mut line_editor = Reedline::create()
        .with_history(history)
        .with_completer(completer)
        .with_quick_completions(true)
        .with_partial_completions(true)
        .with_highlighter(Box::new(ExampleHighlighter::new(commands)))
        .with_hinter(Box::new(DefaultHinter::default()))
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
        let normal_keybindings = default_vi_normal_keybindings();
        let insert_keybindings = default_vi_insert_keybindings();

        Box::new(Vi::new(insert_keybindings, normal_keybindings))
    } else {
        let keybindings = default_emacs_keybindings();

        Box::new(Emacs::new(keybindings))
    };

    line_editor = line_editor.with_edit_mode(edit_mode);

    // Adding vi as text editor
    line_editor = line_editor.with_buffer_editor("vi".into(), "nu".into());

    let prompt = CustomPrompt {};

    loop {
        let sig = line_editor.read_line(&prompt);

        match sig {
            Ok(Signal::CtrlD) => {
                break Ok(());
            }
            Ok(Signal::Success(buffer)) => {
                if buffer.trim() == "exit" {
                    break Ok(());
                }
                if buffer.trim() == "clear" {
                    line_editor.clear_scrollback().unwrap();
                    continue;
                }
                // Get the full history
                if buffer.trim() == "history" {
                    line_editor.print_history().unwrap();
                    continue;
                }
                if buffer.trim() == "clear-history" {
                    line_editor.history_mut().clear().expect("");
                    continue;
                }

                cli_println!("Our buffer: {buffer}");
            }
            Ok(Signal::CtrlC) => {
                // Prompt has been cleared and should start on the next line
            }
            Err(err) => {
                cli_println!("Error: {err:?}");
            }
        }
    }
}

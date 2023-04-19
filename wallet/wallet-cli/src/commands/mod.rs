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

use clap::Parser;
use reedline::Reedline;

use crate::{cli_println, errors::WalletCliError};

#[derive(Debug, Parser)]
pub enum WalletCommands {
    /// Test subcommand
    Example { some_arg: String },

    /// Quit the REPL
    Exit,

    /// Print history
    History,

    /// Clear screen
    Clear,

    /// Clear history
    ClearHistory,
}

pub fn handle_wallet_command(
    line_editor: &mut Reedline,
    command: WalletCommands,
) -> Result<(), WalletCliError> {
    match command {
        WalletCommands::Example { some_arg } => {
            cli_println!("Example command requests: {some_arg}");
            Ok(())
        }
        WalletCommands::Exit => Err(WalletCliError::Exit),
        WalletCommands::History => {
            line_editor.print_history().expect("Should not fail normally");
            Ok(())
        }
        WalletCommands::Clear => {
            line_editor.clear_scrollback().expect("Should not fail normally");
            Ok(())
        }
        WalletCommands::ClearHistory => {
            line_editor.history_mut().clear().expect("Should not fail normally");
            Ok(())
        }
    }
}

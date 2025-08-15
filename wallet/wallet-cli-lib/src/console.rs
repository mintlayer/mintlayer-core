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

use std::{collections::VecDeque, path::PathBuf};

use crossterm::tty::IsTty;

use wallet_cli_commands::WalletCliCommandError;
use wallet_rpc_lib::types::NodeInterface;

use crate::errors::WalletCliError;

pub trait ConsoleInput: Send + 'static {
    fn is_tty(&self) -> bool;

    fn read_line(&mut self) -> Option<String>;
}

pub trait ConsoleOutput: Send + 'static {
    fn print_line(&mut self, line: &str);

    fn print_error<N: NodeInterface>(&mut self, error: WalletCliError<N>);
}

pub struct StdioInputConsole;

impl ConsoleInput for StdioInputConsole {
    fn is_tty(&self) -> bool {
        std::io::stdin().is_tty()
    }

    fn read_line(&mut self) -> Option<String> {
        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(0) => None,
            Ok(_) => Some(input),
            Err(error) => panic!("stdin read failed unexpectedly: {error}"),
        }
    }
}

pub struct StdioOutputConsole;

impl ConsoleOutput for StdioOutputConsole {
    fn print_line(&mut self, line: &str) {
        println!("{line}");
    }

    fn print_error<N: NodeInterface>(&mut self, error: WalletCliError<N>) {
        if let WalletCliError::WalletCommandError(WalletCliCommandError::InvalidCommandInput(e)) =
            &error
        {
            // Print help and parse errors using styles
            e.print().expect("Should not fail normally");
        } else {
            println!("{error}");
        }
    }
}

pub struct FileInput {
    lines: VecDeque<String>,
}

impl FileInput {
    pub fn new<N: NodeInterface>(file_path: PathBuf) -> Result<Self, WalletCliError<N>> {
        let data = std::fs::read_to_string(&file_path)
            .map_err(|e| WalletCliError::FileError(file_path, e.to_string()))?;
        let lines = data.lines().map(|line| line.to_owned()).collect();
        Ok(Self { lines })
    }
}

impl ConsoleInput for FileInput {
    fn is_tty(&self) -> bool {
        false
    }

    fn read_line(&mut self) -> Option<String> {
        self.lines.pop_front()
    }
}

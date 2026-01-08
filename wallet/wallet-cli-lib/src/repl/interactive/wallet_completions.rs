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

use reedline::{Completer, DefaultCompleter, Span, Suggestion};

/// A wrapper for [reedline::DefaultCompleter] that also returns
/// all available commands if the input is empty.
#[derive(Clone)]
pub struct WalletCompletions {
    external_commands: Vec<String>,
    inner: DefaultCompleter,
}

impl WalletCompletions {
    pub fn new(mut external_commands: Vec<String>) -> Self {
        external_commands.sort();
        let mut completer = DefaultCompleter::with_inclusions(&['-']);
        completer.insert(external_commands.clone());

        WalletCompletions {
            external_commands,
            inner: completer,
        }
    }
}

impl Completer for WalletCompletions {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<reedline::Suggestion> {
        if line.is_empty() {
            self.external_commands
                .iter()
                .map(|cmd| Suggestion {
                    value: cmd.clone(),
                    description: None,
                    extra: None,
                    span: Span::new(0, 0),
                    append_whitespace: false,
                    style: None,
                    match_indices: None,
                })
                .collect()
        } else {
            self.inner.complete(line, pos)
        }
    }
}

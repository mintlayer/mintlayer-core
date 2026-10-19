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

use serde_json::Value;

use crate::ConsoleCommand;

/// The structured result of a wallet command.
///
/// `text` is what users read; `payload`, when present, carries the same result in a
/// machine-readable form for scripting modes.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    text: String,
    payload: Option<Value>,
}

impl CommandOutput {
    /// A result that only has a human-readable form.
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            payload: None,
        }
    }

    /// A result that also carries a machine-readable form of the same data.
    pub fn with_payload(text: impl Into<String>, payload: Value) -> Self {
        Self {
            text: text.into(),
            payload: Some(payload),
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }
}

impl From<CommandOutput> for ConsoleCommand {
    fn from(output: CommandOutput) -> Self {
        match output.payload {
            Some(value) => ConsoleCommand::Json {
                text: Some(output.text),
                value,
            },
            None => ConsoleCommand::Print(output.text),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn payload_produces_json_output() {
        let command: ConsoleCommand = CommandOutput::with_payload("peer count: 3", json!(3)).into();

        let ConsoleCommand::Json { text, value } = command else {
            panic!("expected a Json output");
        };
        assert_eq!(text.as_deref(), Some("peer count: 3"));
        assert_eq!(value, json!(3));
    }

    #[test]
    fn absent_payload_produces_print_output() {
        let command: ConsoleCommand = CommandOutput::plain("done").into();

        let ConsoleCommand::Print(text) = command else {
            panic!("expected a Print output");
        };
        assert_eq!(text, "done");
    }

    #[test]
    fn accessors_return_the_stored_data() {
        let output = CommandOutput::with_payload("text", json!({"key": 1}));
        assert_eq!(output.text(), "text");
        assert_eq!(output.payload(), Some(&json!({"key": 1})));

        let output = CommandOutput::plain("text");
        assert_eq!(output.payload(), None);
    }
}

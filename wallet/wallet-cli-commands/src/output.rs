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
/// machine-readable form. Commands are migrated to this type one by one; a command
/// that has not been migrated keeps returning plain text.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    text: Option<String>,
    payload: Option<Value>,
}

impl CommandOutput {
    /// A result that only has a human-readable form.
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            payload: None,
        }
    }

    /// A result that also carries a machine-readable form of the same data.
    pub fn with_payload(text: impl Into<String>, payload: Value) -> Self {
        Self {
            text: Some(text.into()),
            payload: Some(payload),
        }
    }

    /// A result that only has a machine-readable form. Renderers fall back to a
    /// pretty print of the value when there is no text.
    pub fn value_only(payload: Value) -> Self {
        Self {
            text: None,
            payload: Some(payload),
        }
    }

    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    pub fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }
}

impl From<CommandOutput> for ConsoleCommand {
    fn from(output: CommandOutput) -> Self {
        match output.payload {
            Some(value) => ConsoleCommand::Json {
                text: output.text,
                value,
            },
            None => ConsoleCommand::Print(output.text.unwrap_or_default()),
        }
    }
}

/// The text a text-oriented renderer (REPLs, GUI console) shows for a structured
/// payload: the human-readable text when present, else a pretty print of the value.
pub fn json_display_text(text: Option<String>, value: &Value) -> String {
    match text {
        Some(text) => text,
        None => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
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
        assert_eq!(output.text(), Some("text"));
        assert_eq!(output.payload(), Some(&json!({"key": 1})));

        let output = CommandOutput::plain("text");
        assert_eq!(output.payload(), None);

        let output = CommandOutput::value_only(json!("data"));
        assert_eq!(output.text(), None);
        assert_eq!(output.payload(), Some(&json!("data")));
    }

    #[test]
    fn value_only_produces_json_output_without_text() {
        let command: ConsoleCommand = CommandOutput::value_only(json!("data")).into();

        let ConsoleCommand::Json { text, value } = command else {
            panic!("expected a Json output");
        };
        assert_eq!(text, None);
        assert_eq!(value, json!("data"));
    }

    #[test]
    fn display_text_prefers_the_text_and_falls_back_to_the_value() {
        assert_eq!(
            json_display_text(Some("peer count: 3".to_owned()), &json!(3)),
            "peer count: 3"
        );
        assert_eq!(
            json_display_text(None, &json!({"a": 1})),
            "{\n  \"a\": 1\n}"
        );
    }
}

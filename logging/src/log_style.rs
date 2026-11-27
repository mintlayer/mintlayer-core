// Copyright (c) 2021-2023 RBB S.r.l
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

use std::str::FromStr;

use thiserror::Error;

use crate::utils::{GetFromEnvError, get_from_env};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TextColoring {
    On,
    Off,
    Auto,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LogStyle {
    Text(TextColoring),
    Json,
}

/// The output format of a log sink as chosen on the command line and in the config file.
///
/// This is the part of [`LogStyle`] that does not depend on terminal detection: compared to
/// the `ML_LOG_STYLE` values, only the plain `text` spelling is accepted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

impl LogFormat {
    /// The [`LogStyle`] of this format, with text rendered using the given coloring.
    pub fn to_log_style(self, text_coloring: TextColoring) -> LogStyle {
        match self {
            LogFormat::Text => LogStyle::Text(text_coloring),
            LogFormat::Json => LogStyle::Json,
        }
    }
}

impl FromStr for LogFormat {
    type Err = LogStyleParseError;

    /// Parses `text` or `json` (case-insensitively, like [`LogStyle::parse`]).
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str.to_lowercase().as_str() {
            "json" => Ok(LogFormat::Json),
            "text" => Ok(LogFormat::Text),
            _ => Err(LogStyleParseError::UnrecognizedFormat(str.to_owned())),
        }
    }
}

impl LogStyle {
    pub fn parse(str: &str) -> Result<LogStyle, LogStyleParseError> {
        let str = str.to_lowercase();
        match str.as_str() {
            "json" => Ok(LogStyle::Json),
            "text" => Ok(LogStyle::Text(TextColoring::Auto)),
            "text-colored" => Ok(LogStyle::Text(TextColoring::On)),
            "text-uncolored" => Ok(LogStyle::Text(TextColoring::Off)),
            _ => Err(LogStyleParseError::UnrecognizedFormat(str)),
        }
    }
}

pub fn get_log_style_from_env(env_var_name: &str) -> Result<Option<LogStyle>, LogStyleParseError> {
    get_from_env(env_var_name)?.map(|val| LogStyle::parse(&val)).transpose()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogStyleParseError {
    #[error("Unrecognized format: {0}")]
    UnrecognizedFormat(String),
    #[error("Env var error: {0:?}")]
    GetFromEnvError(#[from] GetFromEnvError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_format_from_str() {
        assert_eq!("text".parse(), Ok(LogFormat::Text));
        assert_eq!("TEXT".parse(), Ok(LogFormat::Text));
        assert_eq!("json".parse(), Ok(LogFormat::Json));
        assert_eq!("Json".parse(), Ok(LogFormat::Json));

        // The colored spellings of `ML_LOG_STYLE` are not accepted here.
        for invalid in ["", "text-colored", "text-uncolored", "jsn"] {
            assert_eq!(
                invalid.parse::<LogFormat>(),
                Err(LogStyleParseError::UnrecognizedFormat(invalid.to_owned()))
            );
        }
    }

    #[test]
    fn log_format_to_log_style() {
        assert_eq!(
            LogFormat::Text.to_log_style(TextColoring::Off),
            LogStyle::Text(TextColoring::Off)
        );
        assert_eq!(
            LogFormat::Text.to_log_style(TextColoring::Auto),
            LogStyle::Text(TextColoring::Auto)
        );
        assert_eq!(
            LogFormat::Json.to_log_style(TextColoring::Auto),
            LogStyle::Json
        );
    }
}

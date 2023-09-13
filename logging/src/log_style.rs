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

use std::ffi::OsString;

use thiserror::Error;

static DEFAULT_LOG_STYLE: LogStyle = LogStyle::Text(TextColoring::Auto);

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

pub fn get_log_style_from_env(env_var_name: &str) -> (LogStyle, Option<LogStyleParseError>) {
    let (style, parse_err) = match std::env::var(env_var_name) {
        Ok(str) => match LogStyle::parse(&str) {
            Ok(style) => (Some(style), None),
            Err(err) => (None, Some(err)),
        },
        Err(std::env::VarError::NotPresent) => (None, None),
        Err(std::env::VarError::NotUnicode(os_str)) => {
            (None, Some(LogStyleParseError::BadData(os_str)))
        }
    };
    (style.unwrap_or(DEFAULT_LOG_STYLE), parse_err)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogStyleParseError {
    #[error("Unrecognized format: {0}")]
    UnrecognizedFormat(String),
    #[error("Bad data: {0:?}")]
    BadData(OsString),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_env_var() {
        std::env::set_var("FOO_VAR", "text");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Text(TextColoring::Auto));
        assert_eq!(error, None);

        std::env::set_var("FOO_VAR", "text-colored");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Text(TextColoring::On));
        assert_eq!(error, None);

        std::env::set_var("FOO_VAR", "text-uncolored");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Text(TextColoring::Off));
        assert_eq!(error, None);

        std::env::set_var("FOO_VAR", "json");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Json);
        assert_eq!(error, None);
    }

    #[test]
    fn parse_env_var_case_insensitive() {
        std::env::set_var("FOO_VAR", "tEXt");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Text(TextColoring::Auto));
        assert_eq!(error, None);

        std::env::set_var("FOO_VAR", "tEXt-coLoRed");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Text(TextColoring::On));
        assert_eq!(error, None);

        std::env::set_var("FOO_VAR", "tEXt-uncoLoRed");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Text(TextColoring::Off));
        assert_eq!(error, None);

        std::env::set_var("FOO_VAR", "jSoN");
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, LogStyle::Json);
        assert_eq!(error, None);
    }

    #[test]
    fn parse_env_var_bad_value() {
        let str = "foo";
        std::env::set_var("FOO_VAR", str);
        let (style, error) = get_log_style_from_env("FOO_VAR");
        assert_eq!(style, DEFAULT_LOG_STYLE);
        assert_eq!(
            error,
            Some(LogStyleParseError::UnrecognizedFormat(str.to_owned()))
        );
    }
}

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

use thiserror::Error;

use crate::utils::{get_from_env, GetFromEnvError};

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

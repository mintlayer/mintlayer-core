// Copyright (c) 2021-2024 RBB S.r.l
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

use std::{borrow::Cow, ffi::OsString};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum GetFromEnvError {
    #[error("Env var {var_name}'s contents are not valid unicode: {data:?}")]
    NotUnicode { var_name: String, data: OsString },
}

pub fn get_from_env(var_name: &str) -> Result<Option<String>, GetFromEnvError> {
    match std::env::var(var_name) {
        Ok(str) => Ok(Some(str)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(data)) => Err(GetFromEnvError::NotUnicode {
            var_name: var_name.to_owned(),
            data,
        }),
    }
}

pub enum ValueOrEnvVar<T> {
    Value(T),
    EnvVar(Cow<'static, str>),
}

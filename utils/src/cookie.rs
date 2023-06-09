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

use std::{
    io,
    path::{Path, PathBuf},
};

pub const COOKIE_FILENAME: &str = ".cookie";

#[derive(thiserror::Error, Debug)]
pub enum LoadCookieError {
    #[error("Failed to read cookie file {path:?}: {source}")]
    Io { source: io::Error, path: PathBuf },
    #[error("Invalid cookie file {path:?}: ':' not found")]
    Format { path: PathBuf },
}

pub fn load_cookie(path: impl AsRef<Path>) -> Result<(String, String), LoadCookieError> {
    let content = std::fs::read_to_string(path.as_ref()).map_err(|e| LoadCookieError::Io {
        source: e,
        path: path.as_ref().to_owned(),
    })?;
    let (username, password) = content.split_once(':').ok_or_else(|| LoadCookieError::Format {
        path: path.as_ref().to_owned(),
    })?;
    Ok((username.to_owned(), password.to_owned()))
}

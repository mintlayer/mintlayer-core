// Copyright (c) 2022 RBB S.r.l
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

use rusqlite::Error as SqlError;
use std::io::{Error as IoError, ErrorKind};

use storage_core::error::{Fatal, Recoverable};

/// Map IoError into a storage error
pub fn process_io_error(err: IoError) -> storage_core::Error {
    match err.kind() {
        ErrorKind::BrokenPipe
        | ErrorKind::AlreadyExists
        | ErrorKind::PermissionDenied
        | ErrorKind::NotFound => Recoverable::Io(err.kind(), err.to_string()).into(),
        _ => Fatal::Io(err.kind(), err.to_string()).into(),
    }
}

/// Map Sqlite error into a storage error
pub fn process_sqlite_error(err: rusqlite::Error) -> storage_core::Error {
    // TODO Improve error conversions
    match err {
        SqlError::SqliteFailure(err, err_str) => {
            Fatal::InternalError(err_str.unwrap_or_else(|| err.to_string())).into()
        }
        _ => Fatal::InternalError(err.to_string()).into(),
    }
}

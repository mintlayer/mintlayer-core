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

use lmdb::Error;
use std::io::{Error as IoError, ErrorKind};

use storage_core::error::{Fatal, Recoverable};

fn process<T>(err: Error, default: storage_core::Result<T>) -> storage_core::Result<T> {
    match err {
        // Not found is signified by succeeding with a value signifying a missing entry
        Error::NotFound => default,

        // Overwriting a key is not an error
        Error::KeyExist => default,

        // Initialization issues
        Error::Invalid | Error::VersionMismatch => Err(Recoverable::DbInit.into()),

        // Transaction failed to commit
        Error::BadTxn => Err(Recoverable::TransactionFailed.into()),

        // We have exhausted some resource which may become available again later
        Error::ReadersFull | Error::TxnFull | Error::TlsFull => {
            Err(Recoverable::TemporarilyUnavailable.into())
        }

        // These signify an implementation flaw
        err @ (Error::BadDbi
        | Error::Panic
        | Error::CursorFull
        | Error::PageFull
        | Error::BadRslot
        | Error::MapFull
        | Error::MapResized) => Err(Fatal::InternalError(err.to_string()).into()),

        // These signify the database flags are not in sync with the schema
        Error::DbsFull | Error::BadValSize | Error::Incompatible => {
            Err(Fatal::SchemaMismatch.into())
        }

        // These are database corruption issues
        Error::PageNotFound | Error::Corrupted => Err(Fatal::DatabaseCorrupted.into()),

        // Other errors
        Error::Other(errno) => {
            let err = IoError::from_raw_os_error(errno);

            // Try to recover the error from the system to get a more informative message
            let last_err = IoError::last_os_error();
            let same_err = err.kind() == last_err.kind();
            let err = if same_err { last_err } else { err };

            // Classify recoverable vs. fatal I/O errors
            Err(process_io_error(err))
        }
    }
}

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

/// Process an error, returning `Ok(())` for outcomes considered success
pub fn process_with_unit(err: Error) -> storage_core::Result<()> {
    process(err, Ok(()))
}

/// Process an error, returning `Ok(None)` for outcomes considered success
pub fn process_with_none<T>(err: Error) -> storage_core::Result<Option<T>> {
    process(err, Ok(None))
}

/// Process an error with operations where "successful" error codes are not expected
pub fn process_with_err<T>(err: Error) -> storage_core::Result<T> {
    process(err, Err(Fatal::InternalError(err.to_string()).into()))
}

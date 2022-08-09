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

//! Storage errors

/// Recoverable database error
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum Recoverable {
    /// Transaction has failed to execute and its effects have not taken place. This could be e.g.
    /// because of a conflicting transaction front-running this one.
    #[error("Transaction failed")]
    TransactionFailed,

    /// Some resource is temporarily exhausted so the transaction did not succeed.
    /// This could be e.g. exceeding the max number of concurrent readers.
    #[error("The database has temporarily exhausted some resource")]
    TemporarilyUnavailable,

    /// Other recoverable error
    #[error("Unknown database error")]
    Unknown,
}

/// Fatal database error
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum Fatal {
    #[error("Out of storage space")]
    OutOfSpace,
    #[error("Database has been corrupted")]
    DatabaseCorrupted,
    #[error("Database internal error")]
    InternalError,
    #[error("Database schema does not match database settings or contents")]
    SchemaMismatch,
    #[error("Unknown fatal database error")]
    Unknown,
}

/// Database error
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Recoverable(Recoverable),
    #[error("{0}")]
    Fatal(Fatal),
}

impl Error {
    /// Get recoverable error, panicking if this is a fatal error.
    pub fn recoverable(self) -> Recoverable {
        match self {
            Self::Recoverable(e) => e,
            Self::Fatal(e) => {
                logging::log::error!("Fatal database error: {}", e);
                panic!("Fatal database error: {}", e)
            }
        }
    }
}

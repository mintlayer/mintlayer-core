// Copyright (c) 2021-2022 RBB S.r.l
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

/// Blockchain storage error
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, thiserror::Error)]
pub enum Error {
    #[error("Storage error: {0}")]
    Storage(storage::error::Recoverable),
}

impl From<storage::Error> for Error {
    fn from(e: storage::Error) -> Self {
        Error::Storage(e.recoverable())
    }
}

/// Possibly failing result of blockchain storage query
pub type Result<T> = core::result::Result<T, Error>;

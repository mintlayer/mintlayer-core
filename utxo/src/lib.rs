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

mod undo;
mod utxo_impl;

pub use undo::*;
pub use utxo_impl::*;

use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("Attempted to overwrite an existing utxo")]
    OverwritingUtxo,
    #[error(
        "The utxo was marked FRESH in the child cache, but the utxo exists in the parent cache. This can be considered a fatal error."
    )]
    FreshUtxoAlreadyExists,
    #[error("Attempted to spend a UTXO that's already spent")]
    UtxoAlreadySpent,
    #[error("Attempted to spend a non-existing UTXO")]
    NoUtxoFound,
    #[error("Attempted to get the block height of a UTXO source that is based on the mempool")]
    NoBlockchainHeightFound,
    #[error("Database error: `{0}`")]
    DBError(String),
}

impl From<chainstate_types::storage_result::Error> for Error {
    fn from(e: chainstate_types::storage_result::Error) -> Self {
        Error::DBError(format!("{:?}", e))
    }
}

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

use std::sync::Arc;

use chainstate_types::storage_result;
use common::{
    chain::{block::GenBlock, OutPointSourceId},
    primitives::Id,
};
use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq, Clone)]
pub enum Error {
    #[error("Attempted to overwrite an existing utxo")]
    OverwritingUtxo,
    #[error(
        "The utxo was marked FRESH in the child cache, but the utxo exists in the parent cache. This can be considered a fatal error."
    )]
    FreshUtxoAlreadyExists,
    #[error("Attempted to spend a UTXO that's already spent")]
    UtxoAlreadySpent(OutPointSourceId),
    #[error("Attempted to spend a non-existing UTXO")]
    NoUtxoFound,
    #[error("Attempted to get the block height of a UTXO source that is based on the mempool")]
    NoBlockchainHeightFound,
    #[error("Block reward undo info is missing while unspending the utxo for block `{0}`")]
    MissingBlockRewardUndo(Id<GenBlock>),
    #[error("Block reward type is invalid `{0}`")]
    InvalidBlockRewardOutputType(Id<GenBlock>),
    #[error("Database error: `{0}`")]
    DBError(#[from] storage_result::Error),

    /// Error when querying a UtxoView
    ///
    /// TODO: This is a temporary solution. It uses a trait object to handle many possible error
    /// types. The concrete error type depends on the UtxoView used. The error enum here should be
    /// parametrized by the error type rather than hide it, so the information is available at
    /// compilation time. That, however, leads to many call sites having to be updated so it's left
    /// for future updates.
    #[error("View query failed: `{0}`")]
    ViewError(BoxedViewError),
}

impl Error {
    pub fn from_view(e: impl ViewError) -> Self {
        Self::ViewError(BoxedViewError::new(e))
    }
}

/// Trait for arrors that can happen when querying a `UtxosView`
pub trait ViewError: 'static + Send + Sync + std::error::Error {}

impl ViewError for chainstate_types::storage_result::Error {}
impl ViewError for std::convert::Infallible {}

/// Boxed view error is used to suppot the temporary hack mentioned in [Error::ViewError]
#[derive(Debug, Clone)]
pub struct BoxedViewError(Arc<Box<dyn ViewError>>);

impl BoxedViewError {
    fn new(e: impl ViewError) -> Self {
        Self(Arc::new(Box::new(e)))
    }
}

impl std::fmt::Display for BoxedViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for BoxedViewError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for BoxedViewError {}

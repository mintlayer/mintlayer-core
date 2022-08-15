// Copyright (c) 2021 RBB S.r.l
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

use chainstate_types::PropertyQueryError;
use common::{
    chain::{Block, GenBlock},
    primitives::Id,
};

use crate::ConsensusPoWError;

/// A consensus related error.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusVerificationError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Error while loading previous block {0} of block {1} with error {2}")]
    PrevBlockLoadError(Id<GenBlock>, Id<Block>, PropertyQueryError),
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<GenBlock>, Id<Block>),
    #[error("Block consensus type does not match our chain configuration: {0}")]
    ConsensusTypeMismatch(String),
    #[error("PoW error: {0}")]
    PoWError(ConsensusPoWError),
    #[error("Unsupported consensus type")]
    UnsupportedConsensusType,
    #[error("Kernel output was not found in block: {0}")]
    PoSKernelOutputRetrievalFailed(Id<Block>),
}

// Copyright (c) 2021-2025 RBB S.r.l
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

use chainstate::{ChainstateError, StorageCompatibilityCheckError};
use common::{
    address::AddressError,
    chain::Block,
    primitives::{Compact, Id},
};

#[derive(thiserror::Error, Clone, Debug)]
pub enum Error {
    #[error(transparent)]
    ChainstateError(#[from] ChainstateError),

    #[error("Storage creation error: {0}")]
    StorageCreationError(chainstate_storage::Error),

    #[error("Storage compatibility check error: {0}")]
    StorageCompatibilityCheckError(#[from] StorageCompatibilityCheckError),

    #[error("No block ids returned")]
    NoBlockIdsReturned,

    #[error("Block index not found for block {0:x}")]
    BlockIndexNotFound(Id<Block>),

    #[error("Error writing to the output file: {0}")]
    OutputWriteError(String),

    #[error("Non-PoS consensus type in block {0:x}")]
    NonPoSConsensusInBlock(Id<Block>),

    #[error("Address construction error")]
    AddressConstructionError(AddressError),

    #[error("Error unpacking compact target {0:?} to Uint256")]
    BlockCompactTargetUnpackingError(Compact),

    #[error(
        "Obtained blocks are in unexpected order, current height is {}, previous height is {}",
        cur_block_height,
        prev_block_height
    )]
    UnexpectedBlockOrder {
        cur_block_height: u64,
        prev_block_height: u64,
    },

    #[error("Cannot open output file: {error}")]
    CannotOpenOutputFile { error: String },

    #[error("Unexpected output field: {field}")]
    UnexpectedOutputField { field: String },
}

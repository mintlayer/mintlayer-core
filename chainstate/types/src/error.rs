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

use thiserror::Error;

use common::{
    chain::{Block, GenBlock, PoolId},
    primitives::{BlockHeight, Id},
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PropertyQueryError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] crate::storage_result::Error),
    #[error("Best block index not found")]
    BestBlockIndexNotFound,
    #[error("Block not found {0}")]
    BlockNotFound(Id<Block>),
    #[error("Block index not found for block {0}")]
    BlockIndexNotFound(Id<GenBlock>),
    #[error("Block for height {0} not found")]
    BlockForHeightNotFound(BlockHeight),
    #[error("Error obtaining ancestor")]
    GetAncestorError(#[from] GetAncestorError),
    #[error("Genesis block has no header")]
    GenesisHeaderRequested,
    #[error("Stake pool {0} data not found")]
    StakePoolDataNotFound(PoolId),
    #[error("Staker balance for pool {0} overflow")]
    StakerBalanceOverflow(PoolId),
    #[error("Balance of pool {0} not found")]
    PoolBalanceNotFound(PoolId),
    #[error("Invalid starting block height: {0}")]
    InvalidStartingBlockHeightForMainchainBlocks(BlockHeight),
    #[error("Invalid block height range: {start}..{end}")]
    InvalidBlockHeightRange {
        start: BlockHeight,
        end: BlockHeight,
    },
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum GetAncestorError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] crate::storage_result::Error),
    #[error("Invalid ancestor height: sought ancestor with height {ancestor_height} for block with height {block_height}")]
    InvalidAncestorHeight {
        block_height: BlockHeight,
        ancestor_height: BlockHeight,
    },
    #[error("Previous block index not found {0}")]
    PrevBlockIndexNotFound(Id<GenBlock>),
    #[error("Starting point in ancestor getter not found {0}")]
    StartingPointNotFound(Id<GenBlock>),
}

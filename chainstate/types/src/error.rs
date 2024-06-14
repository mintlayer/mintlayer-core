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
    #[error(
        "Previous block index not found; this block: {block_id}, previous block: {prev_block_id}"
    )]
    PrevBlockIndexNotFound {
        block_id: Id<Block>,
        prev_block_id: Id<GenBlock>,
    },
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
    #[error(transparent)]
    InMemoryBlockTreeError(#[from] InMemoryBlockTreeError),
}

// TODO: ideally, this error shouldn't be here, it should be in the `chainstate` crate itself;
// it only exists here because we need to include it into `PropertyQueryError`.
// Perhaps the latter should also be put inside the `chainstate` crate.
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum InMemoryBlockTreeError {
    // Note: `PropertyQueryError` itself may contain `InMemoryBlockTreeError`, so here we must box it.
    #[error("Error querying property: {0}")]
    PropertyQueryError(Box<PropertyQueryError>),
    // Note: String is used to avoid putting indextree::NodeError here, which is non-comparable.
    #[error("Index tree node error: {0}")]
    IndexTreeNodeError(String),
    #[error("Node for id {0} is not in the arena")]
    NodeNotInArena(indextree::NodeId),
    #[error("Non-root node {0} has no parent")]
    NonRootWithoutParent(indextree::NodeId),
    #[error("Node {node_id} belongs to the branch at {nodes_branch_root} but this branch is at {actual_branch_root}")]
    NodeNotInBranch {
        node_id: indextree::NodeId,
        nodes_branch_root: indextree::NodeId,
        actual_branch_root: indextree::NodeId,
    },
    #[error("Block id {0} doesn't correspond to any root node")]
    BlockIdDoesntCorrespondToRoot(Id<Block>),
}

impl From<PropertyQueryError> for InMemoryBlockTreeError {
    fn from(value: PropertyQueryError) -> Self {
        InMemoryBlockTreeError::PropertyQueryError(Box::new(value))
    }
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

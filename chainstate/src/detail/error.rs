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

use chainstate_types::PropertyQueryError;
use common::{
    chain::{Block, GenBlock, Transaction},
    primitives::{BlockDistance, Id},
};
use consensus::ConsensusVerificationError;

use super::{orphan_blocks::OrphanAddError, transaction_verifier::error::ConnectTransactionError};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Error while checking the previous block: {0}")]
    OrphanCheckFailed(#[from] OrphanCheckError),
    #[error("Check block failed: {0}")]
    CheckBlockFailed(#[from] CheckBlockError),
    #[error("Failed to update the internal blockchain state: {0}")]
    StateUpdateFailed(#[from] ConnectTransactionError),
    #[error("Failed to load best block")]
    BestBlockLoadError(PropertyQueryError),
    #[error("Starting from block {0} with current best {1}, failed to find a path of blocks to connect to reorg with error: {2}")]
    InvariantErrorFailedToFindNewChainPath(Id<Block>, Id<GenBlock>, PropertyQueryError),
    #[error("Invariant error: Attempted to connected block that isn't on the tip")]
    InvariantErrorInvalidTip,
    #[error("The previous block not found")]
    PrevBlockNotFound,
    #[error("Block {0} already exists")]
    BlockAlreadyExists(Id<Block>),
    #[error("Failed to commit block state update to database for block: {0} after {1} attempts with error {2}")]
    DatabaseCommitError(Id<Block>, usize, chainstate_storage::Error),
    #[error("Block proof calculation error for block: {0}")]
    BlockProofCalculationError(Id<Block>),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Block has an invalid merkle root")]
    MerkleRootMismatch,
    #[error("Block has an invalid witness merkle root")]
    WitnessMerkleRootMismatch,
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<Block>, Id<Block>),
    #[error("Block time must be equal or higher than the median of its ancestors")]
    BlockTimeOrderInvalid,
    #[error("Block time too far into the future")]
    BlockFromTheFuture,
    #[error("Block size is too large: {0}")]
    BlockSizeError(#[from] BlockSizeError),
    #[error("Check transaction failed: {0}")]
    CheckTransactionFailed(CheckBlockTransactionsError),
    #[error("Check transaction failed: {0}")]
    ConsensusVerificationFailed(ConsensusVerificationError),
    #[error("Block reward maturity distance too short in block {0}: {1} < {2}")]
    InvalidBlockRewardMaturityDistance(Id<Block>, BlockDistance, BlockDistance),
    #[error("Block reward maturity distance invalid in block {0}: {1}")]
    InvalidBlockRewardMaturityDistanceValue(Id<Block>, u64),
    #[error("Invalid block reward output timelock type for block {0}")]
    InvalidBlockRewardMaturityTimelockType(Id<Block>),
    #[error("Invalid block reward output type for block {0}")]
    InvalidBlockRewardOutputType(Id<Block>),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockTransactionsError {
    #[error("Blockchain storage error: {0}")]
    StorageError(chainstate_storage::Error),
    #[error("Duplicate input in transaction {0} in block {1}")]
    DuplicateInputInTransaction(Id<Transaction>, Id<Block>),
    #[error("Duplicate input in block")]
    DuplicateInputInBlock(Id<Block>),
    #[error("Duplicate transaction found in block")]
    DuplicatedTransactionInBlock(Id<Transaction>, Id<Block>),
    #[error("Empty inputs or outputs in transaction found in block")]
    EmptyInputsOutputsInTransactionInBlock(Id<Transaction>, Id<Block>),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum OrphanCheckError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Block index not found")]
    PrevBlockIndexNotFound(PropertyQueryError),
    #[error("Orphan that was submitted legitimately through a local source")]
    LocalOrphan,
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockSizeError {
    #[error("Block header too large (current: {0}, limit: {1})")]
    Header(usize, usize),
    #[error("Block transactions component size too large (current: {0}, limit: {1})")]
    SizeOfTxs(usize, usize),
    #[error("Block smart contracts component size too large (current: {0}, limit: {1})")]
    SizeOfSmartContracts(usize, usize),
}

impl From<OrphanAddError> for Result<(), OrphanCheckError> {
    fn from(err: OrphanAddError) -> Self {
        match err {
            OrphanAddError::BlockAlreadyInOrphanList(_) => Ok(()),
        }
    }
}

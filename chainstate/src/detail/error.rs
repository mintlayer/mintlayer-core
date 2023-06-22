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

use super::{
    orphan_blocks::OrphanAddError,
    transaction_verifier::{
        error::{ConnectTransactionError, TokensError},
        storage::TransactionVerifierStorageError,
    },
};
use chainstate_types::{pos_randomness::PoSRandomnessError, GetAncestorError, PropertyQueryError};
use common::{
    chain::{
        block::{block_body::BlockMerkleTreeError, timestamp::BlockTimestamp},
        Block, GenBlock, PoolId, Transaction,
    },
    primitives::{BlockHeight, Id},
};
use consensus::ConsensusVerificationError;

use thiserror::Error;
use tx_verifier::transaction_verifier::{
    error::{SpendStakeError, TxIndexError},
    storage::HasTxIndexDisabledError,
};

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
    #[error("Failed to load block")]
    BlockLoadError(PropertyQueryError),
    #[error("Starting from block {0} with current best {1}, failed to find a path of blocks to connect to reorg with error: {2}")]
    InvariantErrorFailedToFindNewChainPath(Id<Block>, Id<GenBlock>, PropertyQueryError),
    #[error("Invariant error: Attempted to connected block that isn't on the tip")]
    InvariantErrorInvalidTip,
    #[error("The previous block not found")]
    PrevBlockNotFound,
    #[error("Block at height {0} not found")]
    BlockAtHeightNotFound(BlockHeight),
    #[error("Block {0} already exists")]
    BlockAlreadyExists(Id<Block>),
    #[error("Block {0} has already been processed")]
    BlockAlreadyProcessed(Id<Block>),
    #[error("Block {0} has already been processed and marked as invalid")]
    InvalidBlockAlreadyProcessed(Id<Block>),
    #[error("Block {0} has invalid parent block")]
    InvalidParent(Id<Block>),
    #[error(
        "Failed to commit block data to database for block {0} after {1} attempts with error {2}"
    )]
    BlockCommitError(Id<Block>, usize, chainstate_storage::Error),
    #[error("Failed to commit block status update to database for block {0} after {1} attempts with error {2}")]
    BlockStatusCommitError(Id<Block>, usize, chainstate_storage::Error),
    #[error("Block proof calculation error for block: {0}")]
    BlockProofCalculationError(Id<Block>),
    #[error("TransactionVerifier error: {0}")]
    TransactionVerifierError(#[from] TransactionVerifierStorageError),
    #[error("Changing tx index state is not implemented for existing DB")]
    TxIndexConfigError,
    #[error("Transaction index construction error: {0}")]
    TxIndexConstructionError(#[from] TxIndexError),
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("PoS randomness error: `{0}`")]
    RandomnessError(#[from] PoSRandomnessError),
    #[error("Inconsistent db, block not found after connect: {0}")]
    InvariantBrokenBlockNotFoundAfterConnect(Id<Block>),
    #[error("Error during stake spending: {0}")]
    SpendStakeError(#[from] SpendStakeError),
    #[error("Data of pool {0} not found")]
    PoolDataNotFound(PoolId),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Blockchain storage error: {0}")]
    PropertyQueryError(#[from] PropertyQueryError),
    #[error("Block merkle root calculation failed for block {0} with error: {1}")]
    MerkleRootCalculationFailed(Id<Block>, BlockMerkleTreeError),
    #[error("Block has an invalid merkle root")]
    MerkleRootMismatch,
    #[error("Block has an invalid witness merkle root")]
    WitnessMerkleRootMismatch,
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<GenBlock>, Id<Block>),
    #[error("Previous block with id {0} retrieval error starting from block {1}")]
    PrevBlockRetrievalError(PropertyQueryError, Id<GenBlock>, Id<Block>),
    #[error("Block time ({0:?}) must be equal or higher than the median of its ancestors ({1:?})")]
    BlockTimeOrderInvalid(BlockTimestamp, BlockTimestamp),
    #[error("Block time must be a notch higher than the previous block")]
    BlockTimeStrictOrderInvalid,
    #[error("Block time too far into the future")]
    BlockFromTheFuture,
    #[error("Block size is too large: {0}")]
    BlockSizeError(#[from] BlockSizeError),
    #[error("Check transaction failed: {0}")]
    CheckTransactionFailed(CheckBlockTransactionsError),
    #[error("Consensus verification failed: {0}")]
    ConsensusVerificationFailed(ConsensusVerificationError),
    #[error("Invalid block reward output type for block {0}")]
    InvalidBlockRewardOutputType(Id<Block>),
    #[error("Block reward maturity error: {0}")]
    BlockRewardMaturityError(#[from] tx_verifier::timelock_check::OutputMaturityError),
    #[error("Checkpoint mismatch: expected {0} vs given {1}")]
    CheckpointMismatch(Id<Block>, Id<Block>),
    #[error("Parent checkpoint mismatch at height {0}: expected {1} vs given {2}")]
    ParentCheckpointMismatch(BlockHeight, Id<GenBlock>, Id<GenBlock>),
    #[error("CRITICAL: Failed to retrieve ancestor of submitted block: {0}")]
    GetAncestorError(#[from] GetAncestorError),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockTransactionsError {
    #[error("Blockchain storage error: {0}")]
    StorageError(chainstate_storage::Error),
    #[error("Duplicate input in transaction {0} in block {1}")]
    DuplicateInputInTransaction(Id<Transaction>, Id<Block>),
    #[error("Duplicate input in block")]
    DuplicateInputInBlock(Id<Block>),
    #[error("Number of signatures differs from number of inputs")]
    InvalidWitnessCount,
    #[error("Empty inputs or outputs in transaction found in block")]
    EmptyInputsOutputsInTransactionInBlock(Id<Transaction>, Id<Block>),
    #[error("Tokens error: {0}")]
    TokensError(TokensError),
    #[error("No signature data size is too large: {0} > {1}")]
    NoSignatureDataSizeTooLarge(usize, usize),
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

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum InitializationError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("{0}")]
    PropertyQueryError(#[from] PropertyQueryError),
    #[error("Not at genesis but block at height 1 not available")]
    Block1Missing,
    #[error("Genesis mismatch: {0} according to configuration, {1} inferred from storage")]
    GenesisMismatch(Id<GenBlock>, Id<GenBlock>),
}

impl From<OrphanAddError> for Result<(), OrphanCheckError> {
    fn from(err: OrphanAddError) -> Self {
        match err {
            OrphanAddError::BlockAlreadyInOrphanList(_) => Ok(()),
        }
    }
}

impl HasTxIndexDisabledError for BlockError {
    fn tx_index_disabled_error() -> Self {
        TransactionVerifierStorageError::tx_index_disabled_error().into()
    }
}

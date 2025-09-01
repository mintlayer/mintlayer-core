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

use derive_more::Display;
use thiserror::Error;

use super::{
    block_invalidation::BestChainCandidatesError,
    chainstateref::{EpochSealError, InMemoryReorgError},
    orphan_blocks::OrphanAddError,
    transaction_verifier::{
        error::ConnectTransactionError, storage::TransactionVerifierStorageError,
    },
};
use chainstate_storage::ChainstateStorageVersion;
use chainstate_types::{GetAncestorError, PropertyQueryError};
use common::{
    chain::{
        block::{block_body::BlockMerkleTreeError, timestamp::BlockTimestamp},
        config::MagicBytes,
        Block, GenBlock, PoolId,
    },
    primitives::{time::Time, Amount, BlockHeight, Id},
};
use consensus::ConsensusVerificationError;

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
    #[error("The previous block not found when adding new block {0}")]
    PrevBlockNotFoundForNewBlock(Id<Block>),
    #[error("Block {0} already exists")]
    BlockAlreadyExists(Id<Block>),
    #[error("Block {0} index already exists")]
    BlockIndexAlreadyExists(Id<Block>),
    #[error("Block {0} has already been processed")]
    BlockAlreadyProcessed(Id<Block>),
    #[error("Block {0} has already been processed and marked as invalid")]
    InvalidBlockAlreadyProcessed(Id<Block>),
    #[error("Failed to commit to the DB after {0} attempts: {1}, context: {2}")]
    DbCommitError(usize, chainstate_storage::Error, DbCommittingContext),
    #[error("Block proof calculation error for block: {0}")]
    BlockProofCalculationError(Id<Block>),
    #[error("TransactionVerifier error: {0}")]
    TransactionVerifierError(#[from] TransactionVerifierStorageError),
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("Error during sealing an epoch: {0}")]
    EpochSealError(#[from] EpochSealError),
    #[error("Block data missing for a block with a valid index: {0}")]
    BlockDataMissingForValidBlockIndex(Id<Block>),
    #[error("Error accessing best chain candidates: {0}")]
    BestChainCandidatesAccessorError(BestChainCandidatesError),
    #[error("Tokens accounting error: {0}")]
    TokensAccountingError(#[from] tokens_accounting::Error),
    #[error("In-memory reorg failed: {0}")]
    InMemoryReorgFailed(#[from] InMemoryReorgError),
    #[error("Orders accounting error: {0}")]
    OrdersAccountingError(#[from] orders_accounting::Error),

    #[error("Failed to obtain best block id: {0}")]
    BestBlockIdQueryError(PropertyQueryError),
    #[error("Failed to obtain best block index: {0}")]
    BestBlockIndexQueryError(PropertyQueryError),
    #[error("Failed to obtain block index for block {0}: {1}")]
    BlockIndexQueryError(Id<GenBlock>, PropertyQueryError),
    #[error("Failed to determine if the block {0} is in mainchain: {1}")]
    IsBlockInMainChainQueryError(Id<GenBlock>, PropertyQueryError),
    #[error("Failed to obtain the minimum height with allowed reorgs: {0}")]
    MinHeightForReorgQueryError(PropertyQueryError),

    #[error("Error querying a property: {0}")]
    PropertyQueryError(PropertyQueryError),

    #[error("Starting from block {0} with current best {1}, failed to find a path of blocks to connect to reorg with error: {2}")]
    InvariantErrorFailedToFindNewChainPath(Id<GenBlock>, Id<GenBlock>, PropertyQueryError),
    #[error("Invariant error: Attempted to connected block {0} that isn't on the tip")]
    InvariantErrorInvalidTip(Id<GenBlock>),
    #[error("Attempt to connect invalid block {0}")]
    InvariantErrorAttemptToConnectInvalidBlock(Id<GenBlock>),
    #[error("Disconnected headers")]
    InvariantErrorDisconnectedHeaders,
    #[error("Total pool {pool_id} balance {total_balance:?} is less than the staker's balance {staker_balance:?}; best block height = {best_block_height}")]
    InvariantErrorTotalPoolBalanceLessThanStakers {
        total_balance: Amount,
        staker_balance: Amount,
        pool_id: PoolId,
        best_block_height: BlockHeight,
    },
    #[error("Pool {0} data missing while balance is present; best block height =  {1}")]
    InvariantErrorPoolBalancePresentDataMissing(PoolId, BlockHeight),
    #[error("Pool {0} balance missing while pool data is present; best block height =  {1}")]
    InvariantErrorPoolDataPresentBalanceMissing(PoolId, BlockHeight),

    #[error("Unexpected block height range: first = {0}, second = {1}")]
    UnexpectedHeightRange(BlockHeight, BlockHeight),
}

// Note: this enum isn't supposed to represent a complete error; this is why its elements
// don't include a lower-level error value like PropertyQueryError and it itself doesn't
// implement the Error trait.
#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum DbCommittingContext {
    #[display("committing block {}", _0)]
    Block(Id<Block>),
    #[display("committing block status for block {}", _0)]
    BlockStatus(Id<Block>),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Property query error: {0}")]
    PropertyQueryError(#[from] PropertyQueryError),
    #[error("Block merkle root calculation failed for block {0} with error: {1}")]
    MerkleRootCalculationFailed(Id<Block>, BlockMerkleTreeError),
    #[error("Block has an invalid merkle root")]
    MerkleRootMismatch,
    #[error("Parent block {parent_block_id} of block {block_id} not found in database")]
    ParentBlockMissing {
        block_id: Id<Block>,
        parent_block_id: Id<GenBlock>,
    },
    #[error("Block time ({0:?}) must be equal or higher than the median of its ancestors ({1:?})")]
    BlockTimeOrderInvalid(BlockTimestamp, BlockTimestamp),
    #[error("Block {block_id} time too far into the future (block timestamp = {block_timestamp}, current time = {current_time})")]
    BlockFromTheFuture {
        block_id: Id<Block>,
        block_timestamp: BlockTimestamp,
        current_time: Time,
    },
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
    #[error("Checkpoint mismatch at height {height}: expected {expected:x}, given {given:x}")]
    CheckpointMismatch {
        height: BlockHeight,
        expected: Id<GenBlock>,
        given: Id<GenBlock>,
    },
    #[error("CRITICAL: Failed to retrieve ancestor of submitted block: {0}")]
    GetAncestorError(#[from] GetAncestorError),
    #[error("Attempted to add a block before reorg limit (attempted at height: {0} while current height is: {1} and min allowed is: {2})")]
    AttemptedToAddBlockBeforeReorgLimit(BlockHeight, BlockHeight, BlockHeight),
    #[error("TransactionVerifier error: {0}")]
    TransactionVerifierError(#[from] TransactionVerifierStorageError),
    #[error("Error during sealing an epoch: {0}")]
    EpochSealError(#[from] EpochSealError),
    #[error("Block {block_id} has invalid parent block {parent_block_id}")]
    InvalidParent {
        block_id: Id<Block>,
        parent_block_id: Id<GenBlock>,
    },
    #[error("In-memory reorg failed: {0}")]
    InMemoryReorgFailed(#[from] InMemoryReorgError),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockTransactionsError {
    #[error("Check transaction error: {0}")]
    CheckTransactionError(#[from] tx_verifier::CheckTransactionError),
    #[error("Duplicate input in block: {0}")]
    DuplicateInputInBlock(Id<Block>),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum OrphanCheckError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Property query error: {0}")]
    PropertyQueryError(PropertyQueryError),
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
    #[error("Storage compatibility check error: `{0}`")]
    StorageCompatibilityCheckError(#[from] StorageCompatibilityCheckError),
    #[error("Error initializing best chain candidates: {0}")]
    BestChainCandidatesError(#[from] BestChainCandidatesError),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum StorageCompatibilityCheckError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Storage version is missing in the db")]
    StorageVersionMissing,
    #[error("Magic bytes are missing in the db")]
    MagicBytesMissing,
    #[error("Chain type is missing in the db")]
    ChainTypeMissing,
    #[error(
        "Node cannot load chainstate database because the versions mismatch: db `{0:?}`, app `{1:?}`"
    )]
    ChainstateStorageVersionMismatch(ChainstateStorageVersion, ChainstateStorageVersion),
    #[error(
        "Chain's config magic bytes do not match the one from database : expected `{0:?}`, actual `{1:?}`"
    )]
    ChainConfigMagicBytesMismatch(MagicBytes, MagicBytes),
    #[error("Node's chain type doesn't match the one in the database : db `{0}`, app `{1}`")]
    ChainTypeMismatch(String, String),
}

impl From<OrphanAddError> for Result<(), OrphanCheckError> {
    fn from(err: OrphanAddError) -> Self {
        match err {
            OrphanAddError::BlockAlreadyInOrphanList(_) => Ok(()),
        }
    }
}

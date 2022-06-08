// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach, A. Sinitsyn

use common::{
    chain::{
        block::{Block, BlockConsistencyError},
        SpendError, Spender, Transaction, TxMainChainIndexError, TxMainChainPosition,
    },
    primitives::{Amount, BlockHeight, Compact, Id},
};
use thiserror::Error;

use super::orphan_blocks::OrphanAddError;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockError {
    #[error("Error while checking the previous block")]
    OrphanCheckFailed(OrphanCheckError),
    #[error("Check block failed {0}")]
    CheckBlockFailed(CheckBlockError),
    #[error("Block storage error `{0}`")]
    StorageError(blockchain_storage::Error),
    #[error("Failed to load best block")]
    BestBlockLoadError(PropertyQueryError),
    #[error("Starting from block {0} with current best {1}, failed to find a path of blocks to connect to reorg with error: {2}")]
    InvariantErrorFailedToFindNewChainPath(Id<Block>, Id<Block>, PropertyQueryError),
    #[error("Invariant error: Attempted to connected block that isn't on the tip")]
    InvariantErrorInvalidTip,
    #[error("Failed to find previous block in non-genesis setting")]
    InvariantErrorPrevBlockNotFound,
    #[error("The previous block not found")]
    PrevBlockNotFound,
    #[error("Invalid block source")]
    InvalidBlockSource,
    #[error("Outputs already in the inputs cache")]
    OutputAlreadyPresentInInputsCache,
    #[error("Output is not found in the cache or database")]
    MissingOutputOrSpent,
    #[error("Input of tx {tx_id:?} has an out-of-range output index {source_output_index}")]
    OutputIndexOutOfRange {
        tx_id: Option<Spender>,
        source_output_index: usize,
    },
    #[error("Output was erased in a previous step (possible in reorgs with no cache flushing)")]
    MissingOutputOrSpentOutputErased,
    #[error("Double-spend attempt")]
    DoubleSpendAttempt(Spender),
    #[error("Block disconnect already-unspent (invaraint broken)")]
    InvariantBrokenAlreadyUnspent,
    #[error("Source block index for block reward output not found")]
    InvariantBrokenSourceBlockIndexNotFound,
    #[error("Block distance calculation for maturity failed")]
    BlockHeightArithmeticError,
    #[error("Block reward spent immaturely")]
    ImmatureBlockRewardSpend,
    #[error("Invalid output count")]
    InvalidOutputCount,
    #[error("Input was cached, but could not be found")]
    PreviouslyCachedInputNotFound,
    #[error("Input was cached, but it is erased")]
    PreviouslyCachedInputWasErased,
    #[error("Signature verification failed in transaction")]
    SignatureVerificationFailed,
    #[error("Transaction index found but transaction not found")]
    InvariantErrorTransactionCouldNotBeLoaded(TxMainChainPosition),
    #[error("Transaction index for header found but header not found")]
    InvariantErrorHeaderCouldNotBeLoaded(Id<Block>),
    #[error("Input addition error")]
    InputAdditionError,
    #[error("Output addition error")]
    OutputAdditionError,
    #[error("Block reward addition error for block {0}")]
    RewardAdditionError(Id<Block>),
    #[error("Attempt to print money (total inputs: `{0:?}` vs total outputs `{1:?}`")]
    AttemptToPrintMoney(Amount, Amount),
    #[error("Fee calculation failed (total inputs: `{0:?}` vs total outputs `{1:?}`")]
    TxFeeTotalCalcFailed(Amount, Amount),
    #[error("Addition of all fees in block `{0}` failed")]
    FailedToAddAllFeesOfBlock(Id<Block>),
    #[error("Transaction number `{0}` does not exist in block `{1}`")]
    TxNumWrongInBlock(usize, Id<Block>),
    #[error("Serialization invariant failed for block `{0}`")]
    SerializationInvariantError(Id<Block>),
    #[error("Unexpected numeric type conversion error `{0}`")]
    InternalNumTypeConversionError(Id<Block>),
    #[error("Conversion failed: `{0:?}`")]
    Conversion(String),
    #[error("Block {0:?} already exists")]
    BlockAlreadyExists(Id<Block>),
    #[error("Failed to commit block state update to database for block: {0} after {1} attempts with error {2}")]
    DatabaseCommitError(Id<Block>, usize, blockchain_storage::Error),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusPoWError {
    #[error("Blockchain storage error: {0}")]
    StorageError(blockchain_storage::Error),
    #[error("Invalid Proof of Work for block {0}")]
    InvalidPoW(Id<Block>),
    #[error("Error while loading previous block {0} of block {1} with error {2}")]
    PrevBlockLoadError(Id<Block>, Id<Block>, PropertyQueryError),
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<Block>, Id<Block>),
    #[error("Error while loading ancestor of block {0} at height {1} with error {2}")]
    AncestorAtHeightNotFound(Id<Block>, BlockHeight, PropertyQueryError),
    #[error("No PoW data for block for block")]
    NoPowDataInPreviousBlock,
    #[error("Actual time span of value {0} conversion to uint256 failed")]
    ActualTimeSpanConversionFailed(u64),
    #[error("Target time span of value {0} conversion to uint256 failed")]
    TargetTimeSpanConversionFailed(u64),
    #[error("Decoding bits of block failed: `{0:?}`")]
    DecodingBitsFailed(Compact),
    #[error("Previous bits conversion failed: `{0:?}`")]
    PreviousBitsDecodingFailed(Compact),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusVerificationError {
    #[error("Blockchain storage error: {0}")]
    StorageError(blockchain_storage::Error),
    #[error("Error while loading previous block {0} of block {1} with error {2}")]
    PrevBlockLoadError(Id<Block>, Id<Block>, PropertyQueryError),
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<Block>, Id<Block>),
    #[error("Block consensus type does not match our chain configuration: {0}")]
    ConsensusTypeMismatch(String),
    #[error("PoW error: {0}")]
    PoWError(ConsensusPoWError),
    #[error("Unsupported consensus type")]
    UnsupportedConsensusType,
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockError {
    #[error("Blockchain storage error: {0}")]
    StorageError(blockchain_storage::Error),
    #[error("Block has an invalid merkle root")]
    MerkleRootMismatch,
    #[error("Block has an invalid witness merkle root")]
    WitnessMerkleRootMismatch,
    #[error("Internal block representation is invalid `{0}`")]
    BlockConsistencyError(BlockConsistencyError),
    #[error("Only genesis can have no previous block")]
    InvalidBlockNoPrevBlock,
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<Block>, Id<Block>),
    #[error("Previous block time must be equal or lower")]
    BlockTimeOrderInvalid,
    #[error("Block from the future")]
    BlockFromTheFuture,
    #[error("Block size is too large")]
    BlockTooLarge,
    #[error("Check transaction failed: {0}")]
    CheckTransactionFailed(CheckBlockTransactionsError),
    #[error("Check transaction failed: {0}")]
    ConsensusVerificationFailed(ConsensusVerificationError),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockTransactionsError {
    #[error("Blockchain storage error: {0}")]
    StorageError(blockchain_storage::Error),
    #[error("Duplicate input in transaction {0} in block {1}")]
    DuplicateInputInTransaction(Id<Transaction>, Id<Block>),
    #[error("Duplicate input in block")]
    DuplicateInputInBlock(Id<Block>),
    #[error("Duplicate transaction found in block")]
    DuplicatedTransactionInBlock(Id<Transaction>, Id<Block>),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PropertyQueryError {
    #[error("Blockchain storage error: {0}")]
    StorageError(blockchain_storage::Error),
    #[error("Best block not found")]
    BestBlockNotFound,
    #[error("Best block index not found")]
    BestBlockIndexNotFound,
    #[error("Block not found {0}")]
    BlockNotFound(Id<Block>),
    #[error("Previous block index not found {0}")]
    PrevBlockIndexNotFound(Id<Block>),
    #[error("Block index {0} has no previous block entry in it")]
    BlockIndexHasNoPrevBlock(Id<Block>),
    #[error("Block for height {0} not found")]
    BlockForHeightNotFound(BlockHeight),
    #[error("Invalid previous block value")]
    InvalidInputForPrevBlock,
    #[error("Provided an empty list")]
    InvalidInputEmpty,
    #[error("Invalid ancestor height: sought ancestor with height {ancestor_height} for block with height {block_height}")]
    InvalidAncestorHeight {
        block_height: BlockHeight,
        ancestor_height: BlockHeight,
    },
}

impl PropertyQueryError {
    // TODO: use a trait to cover this
    pub fn into_err_if_storage_error(
        self,
    ) -> Result<PropertyQueryError, blockchain_storage::Error> {
        match self {
            PropertyQueryError::StorageError(e) => Err(e),
            PropertyQueryError::BestBlockNotFound => Ok(self),
            PropertyQueryError::BlockNotFound(_) => Ok(self),
            PropertyQueryError::BlockForHeightNotFound(_) => Ok(self),
            PropertyQueryError::BestBlockIndexNotFound => Ok(self),
            PropertyQueryError::InvalidInputForPrevBlock => Ok(self),
            PropertyQueryError::InvalidInputEmpty => Ok(self),
            PropertyQueryError::PrevBlockIndexNotFound(_) => Ok(self),
            PropertyQueryError::BlockIndexHasNoPrevBlock(_) => Ok(self),
            PropertyQueryError::InvalidAncestorHeight {
                block_height: _,
                ancestor_height: _,
            } => Ok(self),
        }
    }

    pub fn into_err<T>(self, f: fn(Self) -> T) -> T {
        f(self)
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum OrphanCheckError {
    #[error("Blockchain storage error: {0}")]
    StorageError(blockchain_storage::Error),
    #[error("Previous block not found")]
    PrevBlockNotFound,
    #[error("Block index not found")]
    PrevBlockIndexNotFound,
    #[error("Orphan that was submitted legitimately through a local source")]
    LocalOrphan,
}

impl From<blockchain_storage::Error> for ConsensusVerificationError {
    fn from(err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        ConsensusVerificationError::StorageError(err)
    }
}

impl From<blockchain_storage::Error> for CheckBlockError {
    fn from(err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        CheckBlockError::StorageError(err)
    }
}

impl From<blockchain_storage::Error> for OrphanCheckError {
    fn from(err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        OrphanCheckError::StorageError(err)
    }
}

impl From<OrphanCheckError> for BlockError {
    fn from(err: OrphanCheckError) -> Self {
        BlockError::OrphanCheckFailed(err)
    }
}

impl From<blockchain_storage::Error> for PropertyQueryError {
    fn from(err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        PropertyQueryError::StorageError(err)
    }
}

impl From<blockchain_storage::Error> for BlockError {
    fn from(err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        BlockError::StorageError(err)
    }
}

impl From<OrphanAddError> for Result<(), OrphanCheckError> {
    fn from(err: OrphanAddError) -> Self {
        match err {
            OrphanAddError::BlockAlreadyInOrphanList(_) => Ok(()),
        }
    }
}

impl From<SpendError> for BlockError {
    fn from(err: SpendError) -> Self {
        match err {
            SpendError::AlreadySpent(spender) => BlockError::DoubleSpendAttempt(spender),
            SpendError::AlreadyUnspent => BlockError::InvariantBrokenAlreadyUnspent,
            SpendError::OutOfRange {
                tx_id,
                source_output_index,
            } => BlockError::OutputIndexOutOfRange {
                tx_id,
                source_output_index,
            },
        }
    }
}

impl From<BlockConsistencyError> for CheckBlockError {
    fn from(err: BlockConsistencyError) -> Self {
        CheckBlockError::BlockConsistencyError(err)
    }
}

impl From<TxMainChainIndexError> for BlockError {
    fn from(err: TxMainChainIndexError) -> Self {
        match err {
            TxMainChainIndexError::InvalidOutputCount => BlockError::InvalidOutputCount,
            TxMainChainIndexError::SerializationInvariantError(block_id) => {
                BlockError::SerializationInvariantError(block_id)
            }
            TxMainChainIndexError::InvalidTxNumberForBlock(tx_num, block_id) => {
                BlockError::TxNumWrongInBlock(tx_num, block_id)
            }
        }
    }
}

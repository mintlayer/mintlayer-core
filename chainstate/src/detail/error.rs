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
        SpendError, Spender, Transaction, TxMainChainIndexError,
    },
    primitives::{Amount, BlockHeight, Id},
};
use thiserror::Error;

use super::orphan_blocks::OrphanAddError;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockError {
    #[error("Illegal orphan that was submitted by non-local source, e.g., a peer")]
    IllegalOrphan,
    #[error("Orphan that was submitted legitimately through a local source")]
    LocalOrphan,
    #[error("Invariant error: Attempted to connected block that isn't on the tip")]
    InvariantErrorInvalidTip,
    #[error("Failed to find previous block in non-genesis setting")]
    InvariantErrorPrevBlockNotFound,
    #[error("Only genesis can have no previous block")]
    InvalidBlockNoPrevBlock,
    #[error("Block has an invalid merkle root")]
    MerkleRootMismatch,
    #[error("Block has an invalid witness merkle root")]
    WitnessMerkleRootMismatch,
    #[error("Previous block time must be equal or lower")]
    BlockTimeOrderInvalid,
    #[error("Block from the future")]
    BlockFromTheFuture,
    #[error("Block size is too large")]
    BlockTooLarge,
    #[error("Block storage error `{0}`")]
    StorageError(blockchain_storage::Error),
    #[error("Invalid block height `{0}`")]
    InvalidBlockHeight(BlockHeight),
    #[error("Invalid ancestor height: sought ancestor with height {ancestor_height} for block with height {block_height}")]
    InvalidAncestorHeight {
        block_height: BlockHeight,
        ancestor_height: BlockHeight,
    },
    #[error("Invalid Proof of Work")]
    InvalidPoW,
    #[error("The previous block invalid")]
    PrevBlockInvalid,
    #[error("The storage cause failure `{0}`")]
    StorageFailure(blockchain_storage::Error),
    #[error("The block not found")]
    NotFound,
    #[error("Invalid block source")]
    InvalidBlockSource,
    #[error("Duplicate transaction found in block")]
    DuplicatedTransactionInBlock,
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
    InvariantErrorTransactionCouldNotBeLoaded,
    #[error("Input addition error")]
    InputAdditionError,
    #[error("Output addition error")]
    OutputAdditionError,
    #[error("Attempt to print money (total inputs: `{0:?}` vs total outputs `{1:?}`")]
    AttemptToPrintMoney(Amount, Amount),
    #[error("Duplicate input in transaction")]
    DuplicateInputInTransaction(Id<Transaction>),
    #[error("Duplicate input in block")]
    DuplicateInputInBlock(Id<Block>),
    #[error("Transaction number `{0}` does not exist in block `{1}`")]
    TxNumWrongInBlock(usize, Id<Block>),
    #[error("Serialization invariant failed for block `{0}`")]
    SerializationInvariantError(Id<Block>),
    #[error("Unexpected numeric type conversion error `{0}`")]
    InternalNumTypeConversionError(Id<Block>),
    #[error("Internal block representation is invalid `{0}`")]
    BlockConsistencyError(BlockConsistencyError),
    #[error("No PoW data for block")]
    NoPowDataInPreviousBlock,
    #[error("Block consensus type does not match our chain configuration: {0}")]
    ConsensusTypeMismatch(String),
    #[error("Conversion failed: `{0:?}`")]
    Conversion(String),
    #[error("Unsupported consensus type")]
    UnsupportedConsensusType,
    #[error("Block {0:?} already exists")]
    BlockAlreadyExists(Id<Block>),
    #[error("Failed to commit block state update to database for block: {0} after {1} attempts with error {2}")]
    DatabaseCommitError(Id<Block>, usize, blockchain_storage::Error),
}

impl From<blockchain_storage::Error> for BlockError {
    fn from(err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        BlockError::StorageError(err)
    }
}

impl From<OrphanAddError> for Result<(), BlockError> {
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

impl From<BlockConsistencyError> for BlockError {
    fn from(err: BlockConsistencyError) -> Self {
        BlockError::BlockConsistencyError(err)
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

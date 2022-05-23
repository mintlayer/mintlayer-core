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

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlockError {
    #[error("Unknown error")]
    Unknown,
    #[error("Orphan")]
    Orphan,
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
    #[error("Signature verification failed in transaction with id: {0:?}")]
    SignatureVerificationFailed(Id<Transaction>),
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
    #[error("Transaction number `{0}` does not exist in block `{1:?}`")]
    TxNumWrongInBlock(usize, Id<Block>),
    #[error("Serialization invariant failed for block `{0:?}`")]
    SerializationInvariantError(Id<Block>),
    #[error("Unexpected numeric type conversion error `{0:?}`")]
    InternalNumTypeConversionError(Id<Block>),
    #[error("Internal block representation is invalid `{0}`")]
    BlockConsistencyError(BlockConsistencyError),
    #[error("No PoW data for block")]
    NoPowDataInPreviousBlock,
    #[error("Block consensus type does not match our chain configuration: `{0:?}`")]
    ConsensusTypeMismatch(String),
    #[error("Conversion failed: `{0:?}`")]
    Conversion(String),
    #[error("Unsupported consensus type")]
    UnsupportedConsensusType,
}

impl From<blockchain_storage::Error> for BlockError {
    fn from(_err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        BlockError::Unknown
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

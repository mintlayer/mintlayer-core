use common::{
    chain::{block::Block, SpendError, Spender, Transaction, TxMainChainIndexError},
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
    #[error("Output index out of range")]
    OutputIndexOutOfRange,
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
    // To be expanded
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
            SpendError::OutOfRange => BlockError::OutputIndexOutOfRange,
        }
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
            TxMainChainIndexError::InternalNumTypeConversionError(block_id) => {
                BlockError::InternalNumTypeConversionError(block_id)
            }
        }
    }
}

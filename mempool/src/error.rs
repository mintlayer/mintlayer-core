use thiserror::Error;

use common::chain::transaction::Transaction;
use common::chain::OutPoint;
use common::primitives::amount::Amount;
use common::primitives::Id;
use common::primitives::H256;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Mempool is full")]
    MempoolFull,
    #[error(transparent)]
    TxValidationError(TxValidationError),
}

#[derive(Debug, Error)]
pub enum TxValidationError {
    #[error("No Inputs")]
    NoInputs,
    #[error("No Ouputs")]
    NoOutputs,
    #[error("DuplicateInputs")]
    DuplicateInputs,
    #[error("LooseCoinbase")]
    LooseCoinbase,
    #[error("OutPointNotFound {outpoint:?}")]
    OutPointNotFound {
        outpoint: OutPoint,
        tx_id: Id<Transaction>,
    },
    #[error("ExceedsMaxBlockSize")]
    ExceedsMaxBlockSize,
    #[error("TransactionAlreadyInMempool")]
    TransactionAlreadyInMempool,
    #[error("ConflictWithIrreplaceableTransaction")]
    ConflictWithIrreplaceableTransaction,
    #[error("InputValuesOverflow")]
    InputValuesOverflow,
    #[error("OutputValuesOverflow")]
    OutputValuesOverflow,
    #[error("InputsBelowOutputs")]
    InputsBelowOutputs,
    #[error("ReplacementFeeLowerThanOriginal: The replacement transaction has fee {replacement_fee:?}, the original transaction has fee {original_fee:?}")]
    ReplacementFeeLowerThanOriginal {
        replacement_tx: H256,
        replacement_fee: Amount,
        original_tx: H256,
        original_fee: Amount,
    },
    #[error("TooManyPotentialReplacements")]
    TooManyPotentialReplacements,
    #[error("SpendsNewUnconfirmedInput")]
    SpendsNewUnconfirmedOutput,
    #[error("ConflictsFeeOverflow")]
    ConflictsFeeOverflow,
    #[error("TransactionFeeLowerThanConflictsWithDescendants")]
    TransactionFeeLowerThanConflictsWithDescendants,
    #[error("AdditionalFeesUnderflow")]
    AdditionalFeesUnderflow,
    #[error("InsufficientFeesToRelay")]
    InsufficientFeesToRelay { tx_fee: Amount, relay_fee: Amount },
    #[error("InsufficientFeesToRelayRBF")]
    InsufficientFeesToRelayRBF,
    #[error("RollingFeeThresholdNotMet")]
    RollingFeeThresholdNotMet { minimum_fee: Amount, tx_fee: Amount },
    #[error("FeeRate error")]
    FeeRateError,
    #[error("AncestorFeeUpdateOverflow")]
    AncestorFeeUpdateOverflow,
    #[error("Descendant of expired transaction")]
    DescendantOfExpiredTransaction,
    #[error("Internal Error")]
    InternalError,
}

impl From<TxValidationError> for Error {
    fn from(e: TxValidationError) -> Self {
        Error::TxValidationError(e)
    }
}

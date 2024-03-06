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

mod ban_score;

pub use ban_score::MempoolBanScore;
use chainstate::{tx_verifier::error::ConnectTransactionError, ChainstateError};
use subsystem::error::CallError;
use thiserror::Error;

use common::{
    chain::{GenBlock, Transaction},
    primitives::{amount::DisplayAmount, Id, H256},
};

use crate::pool::fee::Fee;

/// Error related to the construction of transaction sequence for inclusion in a block
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BlockConstructionError {
    #[error(transparent)]
    Validity(#[from] TxValidationError),
    #[error("The tip moved during block construction: {0:?} -> {1:?}")]
    TipMoved(Id<GenBlock>, Id<GenBlock>),
    #[error("Subsystem call: {0}")]
    Call(#[from] subsystem::error::CallError),
    #[error("User-requested transaction {0} not found in mempool")]
    TxNotFound(Id<Transaction>),
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Error {
    #[error(transparent)]
    Validity(#[from] TxValidationError),
    #[error(transparent)]
    Policy(#[from] MempoolPolicyError),
    #[error("Orphan transaction error: {0}")]
    Orphan(#[from] OrphanPoolError),
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MempoolPolicyError {
    #[error(transparent)]
    Conflict(#[from] MempoolConflictError),
    #[error("Mempool is full")]
    MempoolFull,
    #[error("Transaction has no inputs.")]
    NoInputs,
    #[error("Transaction has no outputs.")]
    NoOutputs,
    #[error("Transaction exceeds the maximum block size.")]
    ExceedsMaxBlockSize,
    #[error("Replacement transaction has fee lower than the original. Replacement fee is {replacement_fee:?}, original fee {original_fee:?}")]
    ReplacementFeeLowerThanOriginal {
        replacement_tx: H256,
        replacement_fee: Fee,
        original_tx: H256,
        original_fee: Fee,
    },
    #[error("The sum of the fees of this transaction's conflicts overflows.")]
    ConflictsFeeOverflow,
    #[error("Transaction pays a fee that is lower than the fee of its conflicts with their descendants.")]
    TransactionFeeLowerThanConflictsWithDescendants,
    #[error("Underflow in computing transaction's additional fees.")]
    AdditionalFeesUnderflow,
    #[error("Transaction does not pay sufficient fees to be relayed (tx_fee: {tx_fee}, min_relay_fee: {min_relay_fee}).")]
    InsufficientFeesToRelay {
        tx_fee: DisplayAmount,
        min_relay_fee: DisplayAmount,
    },
    #[error("Replacement transaction does not pay enough for its bandwidth.")]
    InsufficientFeesToRelayRBF,
    #[error("Rolling fee threshold not met (fee is {tx_fee}, minimum {minimum_fee}).")]
    RollingFeeThresholdNotMet {
        minimum_fee: DisplayAmount,
        tx_fee: DisplayAmount,
    },
    #[error("Overflow encountered while computing fee with ancestors")]
    AncestorFeeOverflow,
    #[error("Overflow encountered while updating ancestor fee.")]
    AncestorFeeUpdateOverflow,
    #[error("Fee overflow")]
    FeeOverflow,
    #[error("Get parent error")]
    GetParentError,
    #[error("Transaction is a descendant of expired transaction.")]
    DescendantOfExpiredTransaction,
    #[error("Relay fee overflow error")]
    RelayFeeOverflow,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TxValidationError {
    #[error("Chainstate error")]
    ChainstateError(#[from] ChainstateError),
    #[error("Transaction added during initial block download")]
    AddedDuringIBD,
    #[error(transparent)]
    TxValidation(#[from] ConnectTransactionError),
    #[error("Subsystem call error")]
    CallError(#[from] CallError),
    #[error("Tip moved while trying to process transaction")]
    TipMoved,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum OrphanPoolError {
    #[error(transparent)]
    Conflict(#[from] MempoolConflictError),
    #[error("Transaction {0} too large to be accepted into orphan pool (max {1})")]
    TooLarge(usize, usize),
    #[error("Orphan pool full")]
    Full,
    #[error("Account nonces too distant, gap: {0}")]
    NonceGapTooLarge(u64),
    #[error("Conflicts with an irreplaceable transaction in mempool")]
    MempoolConflict,
    #[error("Orphans not supported for transactions originating at {0}")]
    NotSupportedForLocalOrigin(crate::tx_origin::LocalTxOrigin),
}

impl From<ConnectTransactionError> for Error {
    fn from(e: ConnectTransactionError) -> Self {
        TxValidationError::from(e).into()
    }
}

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum MempoolConflictError {
    #[error("Transaction conflicts with another, irreplaceable transaction.")]
    Irreplacable,
    #[error("Replacement transaction spends an unconfirmed input which was not spent by any of the original transactions.")]
    SpendsNewUnconfirmed,
    #[error("Transaction would require too many replacements.")]
    TooManyReplacements,
}

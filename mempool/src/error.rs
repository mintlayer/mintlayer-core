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

use chainstate::ChainstateError;
use subsystem::subsystem::CallError;
use thiserror::Error;

use common::chain::transaction::Transaction;
use common::chain::OutPoint;
use common::primitives::Id;
use common::primitives::H256;

use crate::pool::fee::Fee;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Mempool is full")]
    MempoolFull,
    #[error(transparent)]
    TxValidationError(#[from] TxValidationError),
    #[error("Subsystem failure")]
    SubsystemFailure,
    #[error("Send error")]
    SendError,
    #[error("Receive error")]
    RecvError,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxValidationError {
    #[error("Transaction has no inputs.")]
    NoInputs,
    #[error("Transaction has no outputs.")]
    NoOutputs,
    #[error("Transaction has duplicate inputs.")]
    DuplicateInputs,
    #[error("Outpoint not found: {outpoint:?}")]
    OutPointNotFound {
        outpoint: OutPoint,
        spending_tx_id: Id<Transaction>,
    },
    #[error("Transaction exceeds the maximum block size.")]
    ExceedsMaxBlockSize,
    #[error("Transaction already exists in the mempool.")]
    TransactionAlreadyInMempool,
    #[error("Transaction conflicts with another, irreplaceable transaction.")]
    ConflictWithIrreplaceableTransaction,
    #[error("The sum of the transaction's inputs' values overflows.")]
    InputValuesOverflow,
    #[error("The sum of the transaction's outputs' values overflows.")]
    OutputValuesOverflow,
    #[error("The sum of the transaction's inputs is smaller than the sum of its outputs.")]
    InputsBelowOutputs,
    #[error("Replacement transaction has fee lower than the original. Replacement fee is {replacement_fee:?}, original fee {original_fee:?}")]
    ReplacementFeeLowerThanOriginal {
        replacement_tx: H256,
        replacement_fee: Fee,
        original_tx: H256,
        original_fee: Fee,
    },
    #[error("Transaction would require too many replacements.")]
    TooManyPotentialReplacements,
    #[error("Replacement transaction spends an unconfirmed input which was not spent by any of the original transactions.")]
    SpendsNewUnconfirmedOutput,
    #[error("The sum of the fees of this transaction's conflicts overflows.")]
    ConflictsFeeOverflow,
    #[error("Transaction pays a fee that is lower than the fee of its conflicts with their descendants.")]
    TransactionFeeLowerThanConflictsWithDescendants,
    #[error("Underflow in computing transaction's additional fees.")]
    AdditionalFeesUnderflow,
    #[error("Transaction does not pay sufficient fees to be relayed.")]
    InsufficientFeesToRelay { tx_fee: Fee, relay_fee: Fee },
    #[error("Replacement transaction does not pay enough for its bandwidth.")]
    InsufficientFeesToRelayRBF,
    #[error("Rolling fee threshold not met.")]
    RollingFeeThresholdNotMet { minimum_fee: Fee, tx_fee: Fee },
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
    #[error("Chainstate error")]
    ChainstateError(#[from] ChainstateError),
    #[error("Subsystem call error")]
    CallError(#[from] CallError),
    #[error("Internal Error.")]
    InternalError,
}

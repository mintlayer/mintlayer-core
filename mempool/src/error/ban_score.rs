// Copyright (c) 2023 RBB S.r.l
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

use chainstate::{
    ban_score::BanScore,
    tx_verifier::{
        transaction_verifier::{
            signature_destination_getter::SignatureDestinationGetterError, RewardDistributionError,
        },
        CheckTransactionError,
    },
    ChainstateError, ConnectTransactionError, IOPolicyError, TokensError,
    TransactionVerifierStorageError,
};

use crate::error::{Error, MempoolPolicyError, TxValidationError};

/// Ban score for transactions
pub trait MempoolBanScore {
    fn mempool_ban_score(&self) -> u32;
}

impl MempoolBanScore for Error {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // Validation error, needs further inspection
            Error::Validity(err) => err.mempool_ban_score(),
            // Mempool policy violation, needs further inspection
            Error::Policy(err) => err.mempool_ban_score(),
            // Orphan errors may be race / out of sync errors, allowed
            Error::Orphan(_) => 0,
        }
    }
}

impl MempoolBanScore for MempoolPolicyError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // Basic transaction integrity checks failed, ban peer.
            MempoolPolicyError::NoInputs => 100,
            MempoolPolicyError::NoOutputs => 100,
            MempoolPolicyError::ExceedsMaxBlockSize => 100,
            MempoolPolicyError::RelayFeeOverflow => 100,

            // Errors to do with transaction conflicts and replacements are not punished since the
            // peer may not be aware of all the transactions the node has in the mempool.
            // This could be refined later.
            MempoolPolicyError::Conflict(_) => 0,
            MempoolPolicyError::MempoolFull => 0,
            MempoolPolicyError::ConflictsFeeOverflow => 0,
            MempoolPolicyError::TransactionFeeLowerThanConflictsWithDescendants => 0,
            MempoolPolicyError::ReplacementFeeLowerThanOriginal { .. } => 0,
            MempoolPolicyError::AdditionalFeesUnderflow => 0,

            // Sending transactions with a fee below the minimum should not be punished.
            MempoolPolicyError::InsufficientFeesToRelay { .. } => 0,
            MempoolPolicyError::InsufficientFeesToRelayRBF => 0,

            // Rolling fee may be out of sync
            MempoolPolicyError::RollingFeeThresholdNotMet { .. } => 0,

            // These depend on other transactions we have in the mempool so don't hold the peer
            // liable for these errors. Could be refined later.
            MempoolPolicyError::AncestorFeeOverflow => 0,
            MempoolPolicyError::AncestorFeeUpdateOverflow => 0,
            MempoolPolicyError::FeeOverflow => 0,
            MempoolPolicyError::GetParentError => 0,
            MempoolPolicyError::DescendantOfExpiredTransaction => 0,
        }
    }
}

impl MempoolBanScore for TxValidationError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            TxValidationError::ChainstateError(err) => err.mempool_ban_score(),
            TxValidationError::TxValidation(err) => err.mempool_ban_score(),

            // Unsolicited transaction sent during IBD
            TxValidationError::AddedDuringIBD => 0,

            // Internal errors
            TxValidationError::CallError(_) => 0,
            TxValidationError::TipMoved => 0,
        }
    }
}

impl MempoolBanScore for ChainstateError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // Mempool does not process entire blocks, should not happen
            ChainstateError::ProcessBlockError(_) => 0,

            // Internal errors
            ChainstateError::FailedToInitializeChainstate(_) => 0,
            ChainstateError::FailedToReadProperty(_) => 0,
            ChainstateError::BootstrapError(_) => 0,
            ChainstateError::BlockInvalidatorError(_) => 0,
        }
    }
}

impl MempoolBanScore for ConnectTransactionError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // These depend on the current chainstate. Since it is not easy to determine whether
            // it is the transaction or the current tip that's wrong, we don't punish the peer.
            ConnectTransactionError::MissingOutputOrSpent(_) => 0,
            ConnectTransactionError::TimeLockViolation(_) => 0,
            ConnectTransactionError::NonceIsNotIncremental(..) => 0,

            // These are delegated to the inner error
            ConnectTransactionError::UtxoError(err) => err.mempool_ban_score(),
            ConnectTransactionError::TokensError(err) => err.mempool_ban_score(),
            ConnectTransactionError::TransactionVerifierError(err) => err.mempool_ban_score(),
            ConnectTransactionError::PoSAccountingError(err) => err.mempool_ban_score(),
            ConnectTransactionError::DestinationRetrievalError(err) => err.mempool_ban_score(),
            ConnectTransactionError::TokensAccountingError(err) => err.mempool_ban_score(),
            ConnectTransactionError::RewardDistributionError(err) => err.mempool_ban_score(),
            ConnectTransactionError::CheckTransactionError(err) => err.mempool_ban_score(),

            // Transaction definitely invalid, ban peer
            ConnectTransactionError::MissingTxInputs => 100,
            ConnectTransactionError::AttemptToPrintMoney(_, _) => 100,
            ConnectTransactionError::SignatureVerificationFailed(_) => 100,
            ConnectTransactionError::TxFeeTotalCalcFailed(_, _) => 100,
            ConnectTransactionError::RewardAdditionError(_) => 100,
            ConnectTransactionError::AttemptToSpendBurnedAmount => 100,
            ConnectTransactionError::BurnAmountSumError(_) => 100,
            ConnectTransactionError::SpendStakeError(_) => 100,
            ConnectTransactionError::UnexpectedPoolId(_, _) => 100,
            ConnectTransactionError::NotEnoughPledgeToCreateStakePool(_, _, _) => 100,
            ConnectTransactionError::AttemptToCreateStakePoolFromAccounts => 100,
            ConnectTransactionError::AttemptToCreateDelegationFromAccounts => 100,
            ConnectTransactionError::TotalFeeRequiredOverflow => 100,
            ConnectTransactionError::InsufficientCoinsFee(_, _) => 100,
            ConnectTransactionError::OutputTimelockError(err) => err.ban_score(),
            ConnectTransactionError::IOPolicyError(err, _) => err.ban_score(),
            ConnectTransactionError::ConstrainedValueAccumulatorError(err, _) => err.ban_score(),

            // Should not happen when processing standalone transactions
            ConnectTransactionError::BlockHeightArithmeticError => 0,
            ConnectTransactionError::BlockTimestampArithmeticError => 0,
            ConnectTransactionError::MissingBlockUndo(_) => 0,
            ConnectTransactionError::MissingBlockRewardUndo(_) => 0,
            ConnectTransactionError::TxNumWrongInBlockOnConnect(_, _) => 0,
            ConnectTransactionError::TxNumWrongInBlockOnDisconnect(_, _) => 0,
            ConnectTransactionError::FailedToAddAllFeesOfBlock(_) => 0,

            // Internal errors, not peer's fault
            ConnectTransactionError::InvariantBrokenAlreadyUnspent => 0,
            ConnectTransactionError::BlockIndexCouldNotBeLoaded(_) => 0,
            ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoaded(_) => 0,
            ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(_, _) => 0,
            ConnectTransactionError::UtxoBlockUndoError(_) => 0,
            ConnectTransactionError::AccountingBlockUndoError(_) => 0,
            ConnectTransactionError::StakerBalanceNotFound(_) => 0,
            ConnectTransactionError::PoolDataNotFound(_) => 0,
            ConnectTransactionError::PoolBalanceNotFound(_) => 0,
            ConnectTransactionError::StorageError(_) => 0,
            ConnectTransactionError::UndoFetchFailure => 0,
            ConnectTransactionError::TxVerifierStorage => 0,
            ConnectTransactionError::MissingTxUndo(_) => 0,
            ConnectTransactionError::MissingMempoolTxsUndo => 0,
            ConnectTransactionError::BlockRewardInputOutputMismatch(_, _) => 0,
            ConnectTransactionError::MissingTransactionNonce(_) => 0,
            ConnectTransactionError::FailedToIncrementAccountNonce => 0,
            ConnectTransactionError::AttemptToSpendFrozenToken(_) => 0,
        }
    }
}

impl MempoolBanScore for SignatureDestinationGetterError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            SignatureDestinationGetterError::SpendingOutputInBlockReward => 100,
            SignatureDestinationGetterError::SpendingFromAccountInBlockReward => 100,
            SignatureDestinationGetterError::SigVerifyOfNotSpendableOutput => 100,
            SignatureDestinationGetterError::PoolDataNotFound(_) => 0,
            SignatureDestinationGetterError::DelegationDataNotFound(_) => 0,
            SignatureDestinationGetterError::SigVerifyPoSAccountingError(_) => 100,
            SignatureDestinationGetterError::UtxoOutputNotFound(_) => 0,
            SignatureDestinationGetterError::UtxoViewError(_) => 0,
            SignatureDestinationGetterError::TokenDataNotFound(_) => 0,
            SignatureDestinationGetterError::SigVerifyTokensAccountingError(_) => 100,
        }
    }
}

impl MempoolBanScore for TransactionVerifierStorageError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // These are delegated
            TransactionVerifierStorageError::TokensError(err) => err.mempool_ban_score(),
            TransactionVerifierStorageError::UtxoError(err) => err.mempool_ban_score(),
            TransactionVerifierStorageError::PoSAccountingError(err) => err.mempool_ban_score(),
            TransactionVerifierStorageError::TokensAccountingError(err) => err.mempool_ban_score(),

            // Should not happen in mempool (no undos, no block processing, internal errors)
            TransactionVerifierStorageError::GetAncestorError(_) => 0,
            TransactionVerifierStorageError::StatePersistenceError(_) => 0,
            TransactionVerifierStorageError::GenBlockIndexRetrievalFailed(_) => 0,
            TransactionVerifierStorageError::UtxoBlockUndoError(_) => 0,
            TransactionVerifierStorageError::DuplicateBlockUndo(_) => 0,
            TransactionVerifierStorageError::AccountingBlockUndoError(_) => 0,
        }
    }
}

impl MempoolBanScore for TokensError {
    fn mempool_ban_score(&self) -> u32 {
        // TokensError only involves state-independent transaction validity.
        // We can reuse the ban logic from chainstate here.
        chainstate::ban_score::BanScore::ban_score(self)
    }
}

impl MempoolBanScore for utxo::Error {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // These errors may be caused by out of sync nodes.
            utxo::Error::UtxoAlreadySpent(_) => 0,
            utxo::Error::NoUtxoFound => 0,

            // Transaction invalid
            utxo::Error::InvalidBlockRewardOutputType(_) => 100,

            // Internal errors
            utxo::Error::OverwritingUtxo => 0,
            utxo::Error::FreshUtxoAlreadyExists => 0,
            utxo::Error::NoBlockchainHeightFound => 0,
            utxo::Error::MissingBlockRewardUndo(_) => 0,
            utxo::Error::ViewRead => 0,
            utxo::Error::StorageWrite => 0,
            utxo::Error::TxInputAndUndoMismatch(_) => 0,
        }
    }
}

impl MempoolBanScore for pos_accounting::Error {
    fn mempool_ban_score(&self) -> u32 {
        use pos_accounting::Error as E;
        match self {
            // These may be caused by an out of sync peer
            E::AttemptedDecommissionNonexistingPoolBalance => 0,
            E::AttemptedDecommissionNonexistingPoolData => 0,
            E::DelegationCreationFailedPoolDoesNotExist => 0,
            E::DelegationDeletionFailedIdDoesNotExist => 0,
            E::DelegationDeletionFailedBalanceNonZero => 0,
            E::DelegationDeletionFailedPoolsShareNonZero => 0,
            E::DelegationDeletionFailedPoolStillExists => 0,
            E::DelegateToNonexistingId => 0,
            E::DelegateToNonexistingPool => 0,
            E::IncreaseStakerRewardsOfNonexistingPool => 0,

            // Accounting error has to be inspected further
            E::AccountingError(err) => err.mempool_ban_score(),

            // Internal invariant errors
            E::InvariantErrorPoolBalanceAlreadyExists => 0,
            E::InvariantErrorPoolDataAlreadyExists => 0,
            E::InvariantErrorDelegationCreationFailedIdAlreadyExists => 0,
            E::InvariantErrorPoolCreationReversalFailedBalanceNotFound => 0,
            E::InvariantErrorPoolCreationReversalFailedDataNotFound => 0,
            E::InvariantErrorPoolCreationReversalFailedAmountChanged => 0,
            E::InvariantErrorDelegationShareNotFound => 0,

            // These signify an invalid transaction
            E::AdditionError => 100,
            E::SubError => 100,
            E::DelegationBalanceAdditionError => 100,
            E::DelegationBalanceSubtractionError => 100,
            E::PoolBalanceAdditionError => 100,
            E::PoolBalanceSubtractionError => 100,
            E::DelegationSharesAdditionError => 100,
            E::DelegationSharesSubtractionError => 100,
            E::PledgeValueToSignedError => 100,
            E::StakerBalanceOverflow => 100,

            // Not undo-ing in mempool
            E::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists => 0,
            E::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists => 0,
            E::InvariantErrorDelegationIdUndoFailedNotFound => 0,
            E::InvariantErrorDelegationIdUndoFailedDataConflict => 0,
            E::InvariantErrorDelegationBalanceAdditionUndoError => 0,
            E::InvariantErrorPoolBalanceAdditionUndoError => 0,
            E::InvariantErrorDelegationSharesAdditionUndoError => 0,
            E::InvariantErrorDelegationUndoFailedDataNotFound(_) => 0,
            E::DuplicatesInDeltaAndUndo => 0,
            E::InvariantErrorIncreasePledgeUndoFailedPoolBalanceNotFound => 0,
            E::InvariantErrorIncreaseStakerRewardUndoFailedPoolBalanceNotFound => 0,

            // Internal errors
            E::StorageError(_) => 0,
            E::ViewFail => 0,
        }
    }
}

impl MempoolBanScore for accounting::Error {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // These should not happen with valid transactions
            accounting::Error::ArithmeticErrorDeltaAdditionFailed => 100,
            accounting::Error::ArithmeticErrorSumToSignedFailed => 100,
            accounting::Error::ArithmeticErrorSumToUnsignedFailed => 100,
            accounting::Error::ArithmeticErrorToSignedFailed => 100,
            accounting::Error::ArithmeticErrorToUnsignedFailed => 100,

            // These depend on the current state which may be out of sync
            accounting::Error::DataCreatedMultipleTimes => 0,
            accounting::Error::ModifyNonexistingData => 0,
            accounting::Error::RemoveNonexistingData => 0,
            accounting::Error::DeltaDataCreatedMultipleTimes => 0,
            accounting::Error::DeltaDataDeletedMultipleTimes => 0,
            accounting::Error::DeltaDataModifyAfterDelete => 0,
            accounting::Error::DeltaDataMismatch => 0,

            // Undo not performed in mempool
            accounting::Error::DeltaUndoNegationError => 0,
            accounting::Error::DeltaOverUndoApplied => 0,
        }
    }
}

impl MempoolBanScore for IOPolicyError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            IOPolicyError::InvalidInputTypeInReward => 100,
            IOPolicyError::InvalidOutputTypeInReward => 100,
            IOPolicyError::InvalidInputTypeInTx => 100,
            IOPolicyError::MultiplePoolCreated => 100,
            IOPolicyError::MultipleDelegationCreated => 100,
            IOPolicyError::MultipleAccountCommands => 100,
            IOPolicyError::ProduceBlockInTx => 100,
            IOPolicyError::AttemptToUseAccountInputInReward => 100,
        }
    }
}

impl MempoolBanScore for tokens_accounting::Error {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            tokens_accounting::Error::StorageError(_) => 0,
            tokens_accounting::Error::AccountingError(err) => err.mempool_ban_score(),
            tokens_accounting::Error::TokenAlreadyExists(_) => 0,
            tokens_accounting::Error::TokenDataNotFound(_) => 0,
            tokens_accounting::Error::CirculatingSupplyNotFound(_) => 0,
            tokens_accounting::Error::MintExceedsSupplyLimit(_, _, _) => 0,
            tokens_accounting::Error::AmountOverflow => 100,
            tokens_accounting::Error::CannotMintFromLockedSupply(_) => 100,
            tokens_accounting::Error::CannotUnmintFromLockedSupply(_) => 100,
            tokens_accounting::Error::NotEnoughCirculatingSupplyToUnmint(_, _, _) => 0,
            tokens_accounting::Error::SupplyIsAlreadyLocked(_) => 0,
            tokens_accounting::Error::CannotLockNotLockableSupply(_) => 100,
            tokens_accounting::Error::TokenIsAlreadyFrozen(_) => 0,
            tokens_accounting::Error::CannotFreezeNotFreezableToken(_) => 100,
            tokens_accounting::Error::CannotUnfreezeNotUnfreezableToken(_) => 0,
            tokens_accounting::Error::CannotUnfreezeTokenThatIsNotFrozen(_) => 0,
            tokens_accounting::Error::CannotMintFrozenToken(_) => 0,
            tokens_accounting::Error::CannotUnmintFrozenToken(_) => 0,
            tokens_accounting::Error::CannotLockFrozenToken(_) => 0,
            tokens_accounting::Error::CannotChangeAuthorityForFrozenToken(_) => 0,
            tokens_accounting::Error::ViewFail => 0,
            tokens_accounting::Error::StorageWrite => 0,

            // Undo not performed in mempool
            tokens_accounting::Error::TokenDataNotFoundOnReversal(_) => 0,
            tokens_accounting::Error::CannotUnlockNotLockedSupplyOnReversal(_) => 0,
            tokens_accounting::Error::CannotUndoMintForLockedSupplyOnReversal(_) => 0,
            tokens_accounting::Error::CannotUndoUnmintForLockedSupplyOnReversal(_) => 0,
            tokens_accounting::Error::CannotUndoFreezeTokenThatIsNotFrozen(_) => 0,
            tokens_accounting::Error::CannotUndoUnfreezeTokenThatIsFrozen(_) => 0,
            tokens_accounting::Error::CannotUndoChangeAuthorityForFrozenToken(_) => 0,
        }
    }
}

impl MempoolBanScore for RewardDistributionError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            RewardDistributionError::PoSAccountingError(err) => err.mempool_ban_score(),

            RewardDistributionError::InvariantStakerBalanceGreaterThanPoolBalance(_, _, _) => 100,
            RewardDistributionError::RewardAdditionError(_) => 100,
            RewardDistributionError::StakerRewardCalculationFailed(_, _) => 100,
            RewardDistributionError::StakerRewardCannotExceedTotalReward(_, _, _, _) => 100,
            RewardDistributionError::DistributedDelegationsRewardExceedTotal(_, _, _, _) => 100,

            RewardDistributionError::InvariantPoolBalanceIsZero(_) => 0,
            RewardDistributionError::TotalDelegationBalanceZero(_) => 0,
            RewardDistributionError::PoolDataNotFound(_) => 0,
            RewardDistributionError::PoolBalanceNotFound(_) => 0,
            RewardDistributionError::DelegationRewardOverflow(_, _, _, _) => 0,
            RewardDistributionError::DelegationsRewardSumFailed(_, _) => 0,
            RewardDistributionError::StakerRewardOverflow(_, _, _, _) => 0,
        }
    }
}

impl MempoolBanScore for CheckTransactionError {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            CheckTransactionError::PropertyQueryError(_) => 0,
            CheckTransactionError::DuplicateInputInTransaction(_) => 100,
            CheckTransactionError::InvalidWitnessCount(_) => 100,
            CheckTransactionError::EmptyInputsInTransaction(_) => 100,
            CheckTransactionError::TokensError(err) => err.mempool_ban_score(),
            CheckTransactionError::NoSignatureDataSizeTooLarge(_, _, _) => 100,
            CheckTransactionError::NoSignatureDataNotAllowed(_) => 100,
            CheckTransactionError::DataDepositMaxSizeExceeded(_, _, _) => 100,
            CheckTransactionError::TxSizeTooLarge(_, _, _) => 100,
            CheckTransactionError::DeprecatedTokenOperationVersion(_, _) => 100,
        }
    }
}

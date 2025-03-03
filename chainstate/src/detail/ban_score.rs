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

use chainstate_types::pos_randomness::PoSRandomnessError;
use consensus::{
    BlockSignatureError, ConsensusPoSError, ConsensusPoWError, ConsensusVerificationError,
};
use tx_verifier::{
    timelock_check::OutputMaturityError,
    transaction_verifier::{
        error::SignatureDestinationGetterError, IOPolicyError, RewardDistributionError,
    },
    CheckTransactionError,
};

use super::{
    chainstateref::{EpochSealError, InMemoryReorgError},
    transaction_verifier::{
        error::{ConnectTransactionError, TokensError},
        storage::TransactionVerifierStorageError,
    },
    BlockSizeError, CheckBlockError, CheckBlockTransactionsError, OrphanCheckError,
};
use crate::{BlockError, ChainstateError};
use chainstate_types::GetAncestorError;

// TODO: use a ban_score macro in a form similar to thiserror::Error in order to define the ban score
//       value of an error on the error enum arms instead of separately like in this file

pub trait BanScore {
    fn ban_score(&self) -> u32;
}

impl BanScore for BlockError {
    fn ban_score(&self) -> u32 {
        match self {
            BlockError::StorageError(_) => 0,
            BlockError::OrphanCheckFailed(err) => err.ban_score(),
            BlockError::CheckBlockFailed(err) => err.ban_score(),
            BlockError::StateUpdateFailed(err) => err.ban_score(),
            // Even though this should've been caught by orphans check, its mere presence means
            // a peer sent a block they're not supposed to send.
            BlockError::PrevBlockNotFoundForNewBlock(_) => 100,
            BlockError::BlockAlreadyExists(_) => 0,
            BlockError::BlockIndexAlreadyExists(_) => 0,
            BlockError::BlockAlreadyProcessed(_) => 0,
            BlockError::InvalidBlockAlreadyProcessed(_) => 100,
            BlockError::DbCommitError(_, _, _) => 0,
            BlockError::BlockProofCalculationError(_) => 100,
            BlockError::TransactionVerifierError(err) => err.ban_score(),
            BlockError::PoSAccountingError(err) => err.ban_score(),
            BlockError::EpochSealError(err) => err.ban_score(),
            BlockError::BlockDataMissingForValidBlockIndex(_) => 0,
            BlockError::BestChainCandidatesAccessorError(_) => 0,

            BlockError::BestBlockIdQueryError(_) => 0,
            BlockError::BestBlockIndexQueryError(_) => 0,
            BlockError::BlockIndexQueryError(_, _) => 0,
            BlockError::IsBlockInMainChainQueryError(_, _) => 0,
            BlockError::MinHeightForReorgQueryError(_) => 0,
            BlockError::PropertyQueryError(_) => 0,
            BlockError::InMemoryReorgFailed(err) => err.ban_score(),

            BlockError::InvariantErrorFailedToFindNewChainPath(_, _, _) => 0,
            BlockError::InvariantErrorInvalidTip(_) => 0,
            BlockError::InvariantErrorAttemptToConnectInvalidBlock(_) => 0,
            BlockError::InvariantErrorDisconnectedHeaders => 0,
            BlockError::InvariantErrorTotalPoolBalanceLessThanStakers { .. } => 0,
            BlockError::InvariantErrorPoolBalancePresentDataMissing(_, _) => 0,
            BlockError::InvariantErrorPoolDataPresentBalanceMissing(_, _) => 0,

            BlockError::UnexpectedHeightRange(_, _) => 0,

            BlockError::TokensAccountingError(err) => err.ban_score(),
            BlockError::OrdersAccountingError(err) => err.ban_score(),
        }
    }
}

impl BanScore for OrphanCheckError {
    fn ban_score(&self) -> u32 {
        match self {
            OrphanCheckError::StorageError(_) => 0,
            OrphanCheckError::PropertyQueryError(_) => 0,
            OrphanCheckError::LocalOrphan => 0,
        }
    }
}

impl BanScore for ConnectTransactionError {
    fn ban_score(&self) -> u32 {
        match self {
            ConnectTransactionError::StorageError(_) => 0,
            // Even though this is an invariant error, it stems from referencing a block for reward that doesn't exist
            ConnectTransactionError::MissingOutputOrSpent(_) => 100,
            // Even though this is an invariant error, it stems from a block reward that doesn't exist
            ConnectTransactionError::FailedToAddAllFeesOfBlock(_) => 100,
            ConnectTransactionError::RewardAdditionError(_) => 100,
            ConnectTransactionError::MissingBlockUndo(_) => 0,
            ConnectTransactionError::MissingBlockRewardUndo(_) => 0,
            ConnectTransactionError::MissingTxUndo(_) => 0,
            ConnectTransactionError::UtxoError(err) => err.ban_score(),
            ConnectTransactionError::TokensError(err) => err.ban_score(),
            ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(_, _) => 100,
            ConnectTransactionError::BlockIndexCouldNotBeLoaded(_) => 100,
            ConnectTransactionError::TransactionVerifierError(err) => err.ban_score(),
            ConnectTransactionError::UtxoBlockUndoError(_) => 100,
            ConnectTransactionError::BurnAmountSumError(_) => 100,
            ConnectTransactionError::AttemptToSpendBurnedAmount => 100,
            ConnectTransactionError::PoSAccountingError(err) => err.ban_score(),
            ConnectTransactionError::AccountingBlockUndoError(_) => 100,
            ConnectTransactionError::SpendStakeError(_) => 100,
            ConnectTransactionError::StakerBalanceNotFound(_) => 0,
            ConnectTransactionError::UndoFetchFailure => 0,
            ConnectTransactionError::TxVerifierStorage => 0,
            ConnectTransactionError::UnexpectedPoolId(_, _) => 100,
            ConnectTransactionError::NotEnoughPledgeToCreateStakePool(_, _, _) => 100,
            ConnectTransactionError::NonceIsNotIncremental(..) => 100,
            ConnectTransactionError::AttemptToCreateStakePoolFromAccounts => 100,
            ConnectTransactionError::AttemptToCreateDelegationFromAccounts => 100,
            ConnectTransactionError::MissingTransactionNonce(_) => 100,
            ConnectTransactionError::FailedToIncrementAccountNonce => 0,
            ConnectTransactionError::IOPolicyError(err, _) => err.ban_score(),
            ConnectTransactionError::ConstrainedValueAccumulatorError(err, _) => err.ban_score(),
            ConnectTransactionError::TokensAccountingError(err) => err.ban_score(),
            ConnectTransactionError::TotalFeeRequiredOverflow => 100,
            ConnectTransactionError::InsufficientCoinsFee(_, _) => 100,
            ConnectTransactionError::AttemptToSpendFrozenToken(_) => 100,
            ConnectTransactionError::RewardDistributionError(err) => err.ban_score(),
            ConnectTransactionError::CheckTransactionError(err) => err.ban_score(),
            ConnectTransactionError::InputCheck(e) => e.ban_score(),
            ConnectTransactionError::OrdersAccountingError(err) => err.ban_score(),
            ConnectTransactionError::AttemptToCreateOrderFromAccounts => 100,
        }
    }
}

impl BanScore for tx_verifier::error::InputCheckError {
    fn ban_score(&self) -> u32 {
        self.error().ban_score()
    }
}

impl BanScore for tx_verifier::error::InputCheckErrorPayload {
    fn ban_score(&self) -> u32 {
        match self {
            Self::MissingUtxo(_) => 100,
            Self::UtxoView(e) => e.ban_score(),
            Self::Translation(e) => e.ban_score(),
            Self::Verification(e) => e.ban_score(),
        }
    }
}

impl BanScore for mintscript::translate::TranslationError {
    fn ban_score(&self) -> u32 {
        match self {
            Self::Unspendable
            | Self::IllegalAccountSpend
            | Self::IllegalOutputSpend
            | Self::PoolNotFound(_)
            | Self::DelegationNotFound(_)
            | Self::TokenNotFound(_)
            | Self::OrderNotFound(_) => 100,

            Self::SignatureError(_) => 100,
            Self::PoSAccounting(e) => e.ban_score(),
            Self::TokensAccounting(e) => e.ban_score(),
            Self::OrdersAccounting(e) => e.ban_score(),
        }
    }
}

impl<SE, TE: BanScore, HE> BanScore for mintscript::script::ScriptError<SE, TE, HE> {
    fn ban_score(&self) -> u32 {
        match self {
            Self::Threshold(_) | Self::Signature(_) | Self::Hashlock(_) => 100,
            Self::Timelock(e) => e.ban_score(),
        }
    }
}

impl<CE: BanScore> BanScore for mintscript::checker::TimelockError<CE> {
    fn ban_score(&self) -> u32 {
        match self {
            Self::HeightLocked(_, _)
            | Self::TimestampLocked(_, _)
            | Self::HeightArith
            | Self::TimestampArith => 100,

            Self::Context(e) => e.ban_score(),
        }
    }
}

impl BanScore for tx_verifier::error::TimelockContextError {
    fn ban_score(&self) -> u32 {
        match self {
            Self::TimelockedAccount => 0,
            Self::MissingUtxoSource => 0,
            Self::HeaderLoad(e, _) => e.ban_score(),
        }
    }
}

impl BanScore for OutputMaturityError {
    fn ban_score(&self) -> u32 {
        match self {
            OutputMaturityError::InvalidOutputMaturitySettingType(_) => 100,
            OutputMaturityError::InvalidOutputMaturityDistance(_, _, _) => 100,
        }
    }
}

impl BanScore for SignatureDestinationGetterError {
    fn ban_score(&self) -> u32 {
        match self {
            SignatureDestinationGetterError::SpendingOutputInBlockReward => 100,
            SignatureDestinationGetterError::SpendingFromAccountInBlockReward => 100,
            SignatureDestinationGetterError::SigVerifyOfNotSpendableOutput => 100,
            SignatureDestinationGetterError::PoolDataNotFound(_) => 100,
            SignatureDestinationGetterError::DelegationDataNotFound(_) => 100,
            SignatureDestinationGetterError::PoSAccountingViewError(_) => 100,
            SignatureDestinationGetterError::UtxoOutputNotFound(_) => 100,
            SignatureDestinationGetterError::UtxoViewError(_) => 100,
            SignatureDestinationGetterError::TokenDataNotFound(_) => 100,
            SignatureDestinationGetterError::TokensAccountingViewError(_) => 100,
            SignatureDestinationGetterError::OrdersAccountingViewError(_) => 100,
            SignatureDestinationGetterError::OrderDataNotFound(_) => 0,
        }
    }
}

impl BanScore for TransactionVerifierStorageError {
    fn ban_score(&self) -> u32 {
        match self {
            TransactionVerifierStorageError::StatePersistenceError(_) => 0,
            TransactionVerifierStorageError::GenBlockIndexRetrievalFailed(_) => 100,
            TransactionVerifierStorageError::GetAncestorError(err) => err.ban_score(),
            TransactionVerifierStorageError::DuplicateBlockUndo(_) => 100,
            TransactionVerifierStorageError::TokensError(err) => err.ban_score(),
            TransactionVerifierStorageError::UtxoError(err) => err.ban_score(),
            TransactionVerifierStorageError::UtxoBlockUndoError(_) => 100,
            TransactionVerifierStorageError::PoSAccountingError(err) => err.ban_score(),
            TransactionVerifierStorageError::AccountingBlockUndoError(_) => 100,
            TransactionVerifierStorageError::TokensAccountingError(err) => err.ban_score(),
            TransactionVerifierStorageError::OrdersAccountingError(err) => err.ban_score(),
        }
    }
}

impl BanScore for GetAncestorError {
    fn ban_score(&self) -> u32 {
        match self {
            GetAncestorError::StorageError(_) => 0,
            GetAncestorError::InvalidAncestorHeight {
                block_height: _,
                ancestor_height: _,
            } => 100,
            GetAncestorError::PrevBlockIndexNotFound(_) => 0,
            GetAncestorError::StartingPointNotFound(_) => 0,
        }
    }
}

impl BanScore for CheckBlockError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckBlockError::StorageError(_) => 0,
            CheckBlockError::MerkleRootMismatch => 100,
            // even though this may be an invariant error, we treat it strictly
            CheckBlockError::ParentBlockMissing { .. } => 100,
            CheckBlockError::TransactionVerifierError(err) => err.ban_score(),
            CheckBlockError::BlockTimeOrderInvalid(_, _) => 100,
            CheckBlockError::BlockFromTheFuture { .. } => 100,
            CheckBlockError::BlockSizeError(err) => err.ban_score(),
            CheckBlockError::CheckTransactionFailed(err) => err.ban_score(),
            CheckBlockError::ConsensusVerificationFailed(err) => err.ban_score(),
            CheckBlockError::InvalidBlockRewardOutputType(_) => 100,
            CheckBlockError::MerkleRootCalculationFailed(_, _) => 100,
            CheckBlockError::BlockRewardMaturityError(err) => err.ban_score(),
            CheckBlockError::PropertyQueryError(_) => 100,
            CheckBlockError::CheckpointMismatch(_, _) => 100,
            CheckBlockError::ParentCheckpointMismatch(_, _, _) => 100,
            CheckBlockError::GetAncestorError(_) => 100,
            CheckBlockError::AttemptedToAddBlockBeforeReorgLimit(_, _, _) => 100,
            CheckBlockError::EpochSealError(err) => err.ban_score(),
            CheckBlockError::InvalidParent { .. } => 100,
            CheckBlockError::InMemoryReorgFailed(err) => err.ban_score(),
        }
    }
}

impl BanScore for InMemoryReorgError {
    fn ban_score(&self) -> u32 {
        match self {
            InMemoryReorgError::StorageError(_) => 0,
            InMemoryReorgError::PropertyQueryError(_) => 0,
            InMemoryReorgError::StateUpdateFailed(err) => err.ban_score(),
            InMemoryReorgError::TransactionVerifierError(err) => err.ban_score(),
            InMemoryReorgError::EpochSealError(err) => err.ban_score(),
            InMemoryReorgError::BlockNotFound(_) => 0,
            InMemoryReorgError::MainchainBlockExpected(_) => 0,
            InMemoryReorgError::StepHandlerFailedWhenDisconnectingBlocks {
                error: _,
                error_class: _,
                ban_score,
            } => *ban_score,
        }
    }
}

impl BanScore for TokensError {
    fn ban_score(&self) -> u32 {
        match self {
            TokensError::StorageError(_) => 0,
            TokensError::IssueError(_, _) => 100,
            TokensError::MultipleTokenIssuanceInTransaction(_) => 100,
            TokensError::CoinOrTokenOverflow(_) => 100,
            TokensError::InsufficientTokenFees(_) => 100,
            TokensError::TransferZeroTokens(_, _) => 100,
            TokensError::TokenIdCantBeCalculated => 100,
            TokensError::TokensInBlockReward => 100,
            TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(_) => 100,
            TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(_) => 100,
            TokensError::TokenMetadataUriTooLarge(_) => 100,
        }
    }
}

impl BanScore for CheckBlockTransactionsError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckBlockTransactionsError::CheckTransactionError(err) => err.ban_score(),
            CheckBlockTransactionsError::DuplicateInputInBlock(_) => 100,
        }
    }
}

impl BanScore for CheckTransactionError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckTransactionError::PropertyQueryError(_) => 0,
            CheckTransactionError::DuplicateInputInTransaction(_) => 100,
            CheckTransactionError::EmptyInputsInTransaction(_) => 100,
            CheckTransactionError::TokensError(err) => err.ban_score(),
            CheckTransactionError::InvalidWitnessCount(_) => 100,
            CheckTransactionError::NoSignatureDataNotAllowed(_) => 100,
            CheckTransactionError::NoSignatureDataSizeTooLarge(_, _, _) => 100,
            CheckTransactionError::DataDepositMaxSizeExceeded(_, _, _) => 100,
            CheckTransactionError::TxSizeTooLarge(_, _, _) => 100,
            CheckTransactionError::DeprecatedTokenOperationVersion(_, _) => 100,
            CheckTransactionError::HtlcsAreNotActivated => 100,
            CheckTransactionError::OrdersAreNotActivated(_) => 100,
            CheckTransactionError::AttemptToFillOrderWithZero(_, _) => 100,
            CheckTransactionError::OrdersCurrenciesMustBeDifferent(_) => 100,
            CheckTransactionError::ChangeTokenMetadataUriNotActivated => 100,
            CheckTransactionError::OrdersV1AreNotActivated(_) => 100,
            CheckTransactionError::DeprecatedOrdersCommands(_) => 100,
        }
    }
}

impl BanScore for ConsensusVerificationError {
    fn ban_score(&self) -> u32 {
        match self {
            ConsensusVerificationError::PrevBlockLoadError(_, _, _) => 0,
            ConsensusVerificationError::PrevBlockNotFound(_, _) => 100,
            ConsensusVerificationError::ConsensusTypeMismatch(_) => 100,
            ConsensusVerificationError::PoWError(err) => err.ban_score(),
            ConsensusVerificationError::UnsupportedConsensusType => 100,
            ConsensusVerificationError::PoSError(ref err) => err.ban_score(),
        }
    }
}

impl BanScore for ConsensusPoWError {
    fn ban_score(&self) -> u32 {
        match self {
            ConsensusPoWError::ChainstateError(_) => 0,
            ConsensusPoWError::InvalidPoW(_) => 100,
            ConsensusPoWError::NoInputDataProvided => 100,
            ConsensusPoWError::PoSInputDataProvided => 100,
            ConsensusPoWError::PrevBlockLoadError(_, _) => 0,
            ConsensusPoWError::PrevBlockNotFound(_) => 100,
            ConsensusPoWError::NoPowDataInPreviousBlock => 100,
            ConsensusPoWError::DecodingBitsFailed(_) => 100,
            ConsensusPoWError::PreviousBitsDecodingFailed(_) => 0,
            ConsensusPoWError::InvalidTargetBits(_, _) => 100,
        }
    }
}

impl BanScore for BlockSizeError {
    fn ban_score(&self) -> u32 {
        match self {
            BlockSizeError::Header(_, _) => 100,
            BlockSizeError::SizeOfTxs(_, _) => 100,
            BlockSizeError::SizeOfSmartContracts(_, _) => 100,
        }
    }
}

impl BanScore for ConsensusPoSError {
    fn ban_score(&self) -> u32 {
        match self {
            ConsensusPoSError::StorageError(_) => 0,
            ConsensusPoSError::ChainstateError(_) => 0,
            ConsensusPoSError::PropertyQueryError(_) => 0,
            ConsensusPoSError::StakeKernelHashTooHigh => 100,
            ConsensusPoSError::TimestampViolation(_, _) => 100,
            ConsensusPoSError::NoKernel => 100,
            ConsensusPoSError::KernelOutpointMustBeUtxo => 100,
            ConsensusPoSError::MissingKernelUtxo => 100,
            ConsensusPoSError::NoEpochData => 0,
            ConsensusPoSError::MultipleKernels => 100,
            ConsensusPoSError::BitsToTargetConversionFailed(_) => 100,
            ConsensusPoSError::PrevBlockIndexNotFound(_) => 0,
            ConsensusPoSError::PoolBalanceNotFound(_) => 100,
            ConsensusPoSError::PoSAccountingError(err) => err.ban_score(),
            ConsensusPoSError::RandomnessError(err) => err.ban_score(),
            ConsensusPoSError::PoolDataNotFound(_) => 0,
            ConsensusPoSError::InvalidTarget(_) => 100,
            ConsensusPoSError::DecodingBitsFailed(_) => 100,
            ConsensusPoSError::NotEnoughTimestampsToAverage => 100,
            ConsensusPoSError::TimestampOverflow => 100,
            ConsensusPoSError::TargetConversionError(_) => 100,
            ConsensusPoSError::InvalidTargetBlockTime => 100,
            ConsensusPoSError::InvariantBrokenNotMonotonicBlockTime => 100,
            ConsensusPoSError::FailedToFetchUtxo => 0,
            ConsensusPoSError::BlockSignatureError(err) => err.ban_score(),
            ConsensusPoSError::NoInputDataProvided => 100,
            ConsensusPoSError::PoWInputDataProvided => 100,
            ConsensusPoSError::FailedToSignBlockHeader => 0,
            ConsensusPoSError::FailedReadingBlock(_) => 0,
            ConsensusPoSError::FutureTimestampInThePast => 0,
            ConsensusPoSError::FailedToSignKernel => 0,
            ConsensusPoSError::PoSBlockTimeStrictOrderInvalid(_) => 100,
            ConsensusPoSError::FiniteTotalSupplyIsRequired => 100,
            ConsensusPoSError::UnsupportedConsensusVersion => 100,
            ConsensusPoSError::EffectivePoolBalanceError(_) => 100,
            ConsensusPoSError::EmptyTimespan => 100,
            ConsensusPoSError::FailedToCalculateCappedBalance => 100,
        }
    }
}

impl BanScore for BlockSignatureError {
    fn ban_score(&self) -> u32 {
        match self {
            BlockSignatureError::BlockSignatureNotFound(_) => 100,
            BlockSignatureError::WrongOutputType(_) => 100,
            BlockSignatureError::WrongDestination(_) => 100,
            BlockSignatureError::BadSignature(_) => 100,
        }
    }
}

impl BanScore for PoSRandomnessError {
    fn ban_score(&self) -> u32 {
        match self {
            PoSRandomnessError::InvalidOutputTypeInStakeKernel(_) => 100,
            PoSRandomnessError::VRFDataVerificationFailed(_) => 100,
        }
    }
}

impl BanScore for utxo::Error {
    fn ban_score(&self) -> u32 {
        match self {
            utxo::Error::OverwritingUtxo => 0,
            utxo::Error::FreshUtxoAlreadyExists => 0,
            utxo::Error::UtxoAlreadySpent(_) => 100,
            utxo::Error::NoUtxoFound => 100,
            utxo::Error::NoBlockchainHeightFound => 0,
            utxo::Error::MissingBlockRewardUndo(_) => 0,
            utxo::Error::InvalidBlockRewardOutputType(_) => 100,
            utxo::Error::TxInputAndUndoMismatch(_) => 100,
            utxo::Error::ViewRead => 0,
            utxo::Error::StorageWrite => 0,
        }
    }
}

impl BanScore for pos_accounting::Error {
    fn ban_score(&self) -> u32 {
        use pos_accounting::Error as E;
        match self {
            E::AccountingError(_) => 100,
            E::InvariantErrorPoolBalanceAlreadyExists => 100,
            E::InvariantErrorPoolDataAlreadyExists => 100,
            E::AttemptedDecommissionNonexistingPoolData => 100,
            E::DelegationCreationFailedPoolDoesNotExist => 100,
            E::InvariantErrorDelegationCreationFailedIdAlreadyExists => 100,
            E::DelegateToNonexistingId => 100,
            E::DelegateToNonexistingPool => 100,
            E::SpendingShareOfNonexistingDelegation(_) => 100,
            E::AdditionError => 100,
            E::SubError => 100,
            E::DelegationBalanceAdditionError => 100,
            E::DelegationBalanceSubtractionError => 100,
            E::PoolBalanceAdditionError => 100,
            E::PoolBalanceSubtractionError => 100,
            E::DelegationSharesAdditionError => 100,
            E::DelegationSharesSubtractionError => 100,
            E::InvariantErrorPoolCreationReversalFailedDataNotFound => 100,
            E::InvariantErrorPoolCreationReversalFailedAmountChanged => 100,
            E::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists => 100,
            E::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists => 100,
            E::InvariantErrorDelegationIdUndoFailedNotFound => 100,
            E::InvariantErrorDelegationIdUndoFailedDataConflict => 100,
            E::InvariantErrorDelegationBalanceAdditionUndoError => 100,
            E::InvariantErrorPoolBalanceAdditionUndoError => 100,
            E::InvariantErrorDelegationSharesAdditionUndoError => 100,
            E::InvariantErrorDelegationShareNotFound => 100,
            E::PledgeValueToSignedError => 100,
            E::InvariantErrorDelegationUndoFailedDataNotFound(_) => 100,
            E::DuplicatesInDeltaAndUndo => 100,
            E::ViewFail => 0,
            E::StorageWrite => 0,
            E::IncreaseStakerRewardsOfNonexistingPool => 100,
            E::StakerBalanceOverflow => 100,
            E::InvariantErrorIncreasePledgeUndoFailedPoolBalanceNotFound => 100,
            E::InvariantErrorIncreaseStakerRewardUndoFailedPoolBalanceNotFound => 100,
            E::DelegationDeletionFailedIdDoesNotExist => 100,
            E::DelegationDeletionFailedBalanceNonZero => 100,
            E::DelegationDeletionFailedPoolsShareNonZero => 100,
            E::DelegationDeletionFailedPoolStillExists => 100,
            E::InvariantErrorNonZeroBalanceForNonExistingDelegation => 100,
        }
    }
}

impl BanScore for ChainstateError {
    fn ban_score(&self) -> u32 {
        match self {
            ChainstateError::FailedToInitializeChainstate(_) => 0,
            ChainstateError::ProcessBlockError(e) => e.ban_score(),
            ChainstateError::FailedToReadProperty(_) => 0,
            ChainstateError::BootstrapError(_) => 0,
            ChainstateError::BlockInvalidatorError(_) => 0,
        }
    }
}

impl BanScore for EpochSealError {
    fn ban_score(&self) -> u32 {
        match self {
            EpochSealError::StorageError(_) => 0,
            EpochSealError::PoSAccountingError(err) => err.ban_score(),
            EpochSealError::SpendStakeError(_) => 100,
            EpochSealError::RandomnessError(err) => err.ban_score(),
            EpochSealError::PoolDataNotFound(_) => 0,
        }
    }
}

impl BanScore for IOPolicyError {
    fn ban_score(&self) -> u32 {
        match self {
            IOPolicyError::InvalidInputTypeInReward => 100,
            IOPolicyError::InvalidOutputTypeInReward => 100,
            IOPolicyError::InvalidInputTypeInTx => 100,
            IOPolicyError::MultiplePoolCreated => 100,
            IOPolicyError::MultipleDelegationCreated => 100,
            IOPolicyError::ProduceBlockInTx => 100,
            IOPolicyError::MultipleAccountCommands => 100,
            IOPolicyError::AttemptToUseAccountInputInReward => 100,
        }
    }
}

impl BanScore for constraints_value_accumulator::Error {
    fn ban_score(&self) -> u32 {
        match self {
            constraints_value_accumulator::Error::AmountOverflow => 100,
            constraints_value_accumulator::Error::CoinOrTokenOverflow(_) => 100,
            constraints_value_accumulator::Error::AttemptToPrintMoney(_) => 100,
            constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(_) => 100,
            constraints_value_accumulator::Error::InputsAndInputsUtxosLengthMismatch(_, _) => 100,
            constraints_value_accumulator::Error::MissingOutputOrSpent(_) => 100,
            constraints_value_accumulator::Error::PoSAccountingError(err) => err.ban_score(),
            constraints_value_accumulator::Error::PledgeAmountNotFound(_) => 100,
            constraints_value_accumulator::Error::SpendingNonSpendableOutput(_) => 100,
            constraints_value_accumulator::Error::AttemptToViolateFeeRequirements => 100,
            constraints_value_accumulator::Error::DelegationBalanceNotFound(_) => 0,
            constraints_value_accumulator::Error::AccountBalanceNotFound(_) => 0,
            constraints_value_accumulator::Error::NegativeAccountBalance(_) => 100,
            constraints_value_accumulator::Error::UnsupportedTokenVersion => 100,
            constraints_value_accumulator::Error::OrdersAccountingError(err) => err.ban_score(),
            constraints_value_accumulator::Error::TokensAccountingError(err) => err.ban_score(),
        }
    }
}

impl BanScore for tokens_accounting::Error {
    fn ban_score(&self) -> u32 {
        match self {
            tokens_accounting::Error::StorageError(_) => 0,
            tokens_accounting::Error::AccountingError(_) => 100,
            tokens_accounting::Error::TokenAlreadyExists(_) => 100,
            tokens_accounting::Error::TokenDataNotFound(_) => 100,
            tokens_accounting::Error::TokenDataNotFoundOnReversal(_) => 100,
            tokens_accounting::Error::MintExceedsSupplyLimit(_, _, _) => 100,
            tokens_accounting::Error::AmountOverflow => 100,
            tokens_accounting::Error::CannotMintFromLockedSupply(_) => 100,
            tokens_accounting::Error::CannotUnmintFromLockedSupply(_) => 100,
            tokens_accounting::Error::NotEnoughCirculatingSupplyToUnmint(_, _, _) => 100,
            tokens_accounting::Error::SupplyIsAlreadyLocked(_) => 100,
            tokens_accounting::Error::CannotLockNotLockableSupply(_) => 100,
            tokens_accounting::Error::CannotUnlockNotLockedSupplyOnReversal(_) => 100,
            tokens_accounting::Error::CannotUndoMintForLockedSupplyOnReversal(_) => 100,
            tokens_accounting::Error::CannotUndoUnmintForLockedSupplyOnReversal(_) => 100,
            tokens_accounting::Error::TokenIsAlreadyFrozen(_) => 100,
            tokens_accounting::Error::CannotFreezeNotFreezableToken(_) => 100,
            tokens_accounting::Error::CannotUnfreezeNotUnfreezableToken(_) => 100,
            tokens_accounting::Error::CannotUnfreezeTokenThatIsNotFrozen(_) => 100,
            tokens_accounting::Error::CannotUndoFreezeTokenThatIsNotFrozen(_) => 100,
            tokens_accounting::Error::CannotUndoUnfreezeTokenThatIsFrozen(_) => 100,
            tokens_accounting::Error::CannotMintFrozenToken(_) => 100,
            tokens_accounting::Error::CannotUnmintFrozenToken(_) => 100,
            tokens_accounting::Error::CannotLockFrozenToken(_) => 100,
            tokens_accounting::Error::CannotChangeAuthorityForFrozenToken(_) => 100,
            tokens_accounting::Error::CannotUndoChangeAuthorityForFrozenToken(_) => 100,
            tokens_accounting::Error::CannotChangeMetadataUriForFrozenToken(_) => 100,
            tokens_accounting::Error::CannotUndoChangeMetadataUriForFrozenToken(_) => 100,
            tokens_accounting::Error::InvariantErrorNonZeroSupplyForNonExistingToken => 100,
            tokens_accounting::Error::ViewFail => 0,
            tokens_accounting::Error::StorageWrite => 0,
        }
    }
}

impl BanScore for RewardDistributionError {
    fn ban_score(&self) -> u32 {
        match self {
            RewardDistributionError::PoSAccountingError(err) => err.ban_score(),
            RewardDistributionError::InvariantPoolBalanceIsZero(_) => 100,
            RewardDistributionError::InvariantStakerBalanceGreaterThanPoolBalance(_, _, _) => 100,
            RewardDistributionError::RewardAdditionError(_) => 100,
            RewardDistributionError::TotalDelegationBalanceZero(_) => 100,
            RewardDistributionError::PoolDataNotFound(_) => 0,
            RewardDistributionError::StakerRewardCalculationFailed(_, _) => 100,
            RewardDistributionError::StakerRewardCannotExceedTotalReward(_, _, _, _) => 100,
            RewardDistributionError::DistributedDelegationsRewardExceedTotal(_, _, _, _) => 100,
            RewardDistributionError::DelegationRewardOverflow(_, _, _, _) => 100,
            RewardDistributionError::DelegationsRewardSumFailed(_, _) => 100,
            RewardDistributionError::StakerRewardOverflow(_, _, _, _) => 100,
        }
    }
}

impl BanScore for orders_accounting::Error {
    fn ban_score(&self) -> u32 {
        use orders_accounting::Error;
        match self {
            Error::StorageError(_) => 0,
            Error::AccountingError(_) => 100,
            Error::OrderAlreadyExists(_) => 100,
            Error::OrderDataNotFound(_) => 100,
            Error::OrderWithZeroValue(_) => 100,
            Error::InvariantOrderDataNotFoundForUndo(_) => 100,
            Error::InvariantOrderAskBalanceChangedForUndo(_) => 100,
            Error::InvariantOrderGiveBalanceChangedForUndo(_) => 100,
            Error::InvariantOrderDataExistForConcludeUndo(_) => 100,
            Error::InvariantOrderAskBalanceExistForConcludeUndo(_) => 100,
            Error::InvariantOrderGiveBalanceExistForConcludeUndo(_) => 100,
            Error::OrderOverflow(_) => 100,
            Error::OrderOverbid(_, _, _) => 100,
            Error::OrderUnderbid(_, _) => 100,
            Error::AttemptedConcludeNonexistingOrderData(_) => 100,
            Error::InvariantNonzeroAskBalanceForMissingOrder(_) => 100,
            Error::InvariantNonzeroGiveBalanceForMissingOrder(_) => 100,
            Error::UnsupportedTokenVersion => 100,
            Error::ViewFail => 0,
            Error::StorageWrite => 0,
        }
    }
}

// TODO: tests in which we simulate every possible case and test the score

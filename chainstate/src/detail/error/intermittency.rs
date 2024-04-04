// Copyright (c) 2024 RBB S.r.l
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

use chainstate_storage::Error as StorageError;
use tx_verifier::transaction_verifier::signature_destination_getter;

pub enum Intermittency {
    /// Error is temporary, retrying the operation that produced it might make it go away.
    Temporary(StorageError),

    /// Error is final, no point retrying.
    Final,
}

impl Intermittency {
    /// We use this if there is insufficient information about the error. Make it temporary so we
    /// retry to be on the safe side (it is OK to retry final errors, just inefficient).
    const UNKNOWN: Self = Self::Temporary(StorageError::Storage(
        storage_core::error::Recoverable::TemporarilyUnavailable,
    ));
}

/// Separate out temporary and final errors in a result.
///
/// Usage:
/// ```ignore
/// match intermittency::classify(some_operation())? {
///     Ok(result) => process_result(result),
///     Err(_temporary_error) => retry(),
/// }
/// ```
pub fn classify<T, E: CheckIntermittency>(res: Result<T, E>) -> Result<Result<T, StorageError>, E> {
    match res {
        Ok(r) => Ok(Ok(r)),
        Err(e) => match e.check_intermittency() {
            Intermittency::Temporary(e) => Ok(Err(e)),
            Intermittency::Final => Err(e),
        },
    }
}

pub trait CheckIntermittency {
    fn check_intermittency(&self) -> Intermittency;
}

impl CheckIntermittency for storage_core::error::Recoverable {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            e @ (Self::TransactionFailed | Self::TemporarilyUnavailable | Self::MemMapFull) => {
                Intermittency::Temporary(chainstate_storage::Error::Storage(e.clone()))
            }
            Self::DbInit | Self::Io(_, _) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for chainstate_storage::Error {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::Storage(e) => e.check_intermittency(),
        }
    }
}

impl CheckIntermittency for crate::BlockError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::OrphanCheckFailed(e) => e.check_intermittency(),
            Self::CheckBlockFailed(e) => e.check_intermittency(),
            Self::StateUpdateFailed(e) => e.check_intermittency(),
            Self::TransactionVerifierError(e) => e.check_intermittency(),
            Self::PoSAccountingError(e) => e.check_intermittency(),
            Self::EpochSealError(e) => e.check_intermittency(),
            Self::BestChainCandidatesAccessorError(e) => e.check_intermittency(),
            Self::TokensAccountingError(e) => e.check_intermittency(),
            Self::DbCommitError(_, e, _) => e.check_intermittency(),
            Self::BestBlockIdQueryError(e)
            | Self::BestBlockIndexQueryError(e)
            | Self::BlockIndexQueryError(_, e)
            | Self::IsBlockInMainChainQueryError(_, e)
            | Self::MinHeightForReorgQueryError(e)
            | Self::PropertyQueryError(e)
            | Self::InvariantErrorFailedToFindNewChainPath(_, _, e) => e.check_intermittency(),

            Self::PrevBlockNotFoundForNewBlock(_)
            | Self::BlockAlreadyExists(_)
            | Self::BlockIndexAlreadyExists(_)
            | Self::BlockAlreadyProcessed(_)
            | Self::BlockProofCalculationError(_)
            | Self::BlockDataMissingForValidBlockIndex(_)
            | Self::InvariantErrorInvalidTip(_)
            | Self::InvariantErrorAttemptToConnectInvalidBlock(_)
            | Self::InvariantErrorDisconnectedHeaders
            | Self::InvalidBlockAlreadyProcessed(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for crate::PropertyQueryError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::GetAncestorError(e) => e.check_intermittency(),

            Self::BestBlockIndexNotFound
            | Self::BlockNotFound(_)
            | Self::BlockIndexNotFound(_)
            | Self::PrevBlockIndexNotFound { .. }
            | Self::BlockForHeightNotFound(_)
            | Self::GenesisHeaderRequested
            | Self::StakePoolDataNotFound(_)
            | Self::StakerBalanceOverflow(_)
            | Self::PoolBalanceNotFound(_)
            | Self::InvalidStartingBlockHeightForMainchainBlocks(_)
            | Self::InvalidBlockHeightRange { .. } => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for chainstate_types::GetAncestorError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),

            Self::InvalidAncestorHeight { .. }
            | Self::PrevBlockIndexNotFound(_)
            | Self::StartingPointNotFound(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for crate::BlockInvalidatorError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::BlocksDisconnectionError {
                disconnect_until: _,
                error: e,
            }
            | Self::BlockStatusUpdateError(_, e)
            | Self::GenericReorgError(e) => e.check_intermittency(),
            Self::DelBlockIndexError(_, e) => e.check_intermittency(),
            Self::BlockIndicesForBranchQueryError(e)
            | Self::IsBlockInMainChainQueryError(_, e)
            | Self::MinHeightForReorgQueryError(e)
            | Self::BestBlockIndexQueryError(e)
            | Self::BlockIndexQueryError(_, e)
            | Self::BlockQueryError(_, e) => e.check_intermittency(),
            Self::StorageError(e) | Self::DbCommitError(_, e, _) => e.check_intermittency(),
            Self::BestChainCandidatesError(e) => e.check_intermittency(),

            Self::BlockTooDeepToInvalidate(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for crate::detail::BlockIntegrationError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::BlockCommitError(_, _, e) => e.check_intermittency(),
            Self::ConnectBlockErrorDuringReorg(e, _, _)
            | Self::OtherReorgError(e, _)
            | Self::BlockCheckError(e, _)
            | Self::OtherNonValidationError(e) => e.check_intermittency(),
        }
    }
}

impl CheckIntermittency for crate::detail::block_invalidation::BestChainCandidatesError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::PropertyQueryError(e) => e.check_intermittency(),
        }
    }
}

impl CheckIntermittency for crate::OrphanCheckError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            crate::OrphanCheckError::StorageError(e) => e.check_intermittency(),
            crate::OrphanCheckError::PropertyQueryError(e) => e.check_intermittency(),
            crate::OrphanCheckError::LocalOrphan => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for crate::CheckBlockError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::PropertyQueryError(e) => e.check_intermittency(),
            Self::StateUpdateFailed(e) => e.check_intermittency(),
            Self::CheckTransactionFailed(e) => e.check_intermittency(),
            Self::ConsensusVerificationFailed(e) => e.check_intermittency(),
            Self::GetAncestorError(e) => e.check_intermittency(),
            Self::TransactionVerifierError(e) => e.check_intermittency(),
            Self::EpochSealError(e) => e.check_intermittency(),

            Self::MerkleRootCalculationFailed(_, _)
            | Self::MerkleRootMismatch
            | Self::ParentBlockMissing { .. }
            | Self::BlockNotFoundDuringInMemoryReorg(_)
            | Self::BlockTimeOrderInvalid(_, _)
            | Self::BlockFromTheFuture(_)
            | Self::BlockSizeError(_)
            | Self::InvalidBlockRewardOutputType(_)
            | Self::BlockRewardMaturityError(_)
            | Self::CheckpointMismatch(_, _)
            | Self::ParentCheckpointMismatch(_, _, _)
            | Self::AttemptedToAddBlockBeforeReorgLimit(_, _, _)
            | Self::InvalidParent { .. } => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tx_verifier::error::ConnectTransactionError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::TransactionVerifierError(e) => e.check_intermittency(),
            Self::PoSAccountingError(e) => e.check_intermittency(),
            Self::UtxoError(e) => e.check_intermittency(),
            Self::TokensError(e) => e.check_intermittency(),
            Self::UtxoBlockUndoError(e) => e.check_intermittency(),
            Self::AccountingBlockUndoError(e) => e.check_intermittency(),
            Self::DestinationRetrievalError(e) => e.check_intermittency(),
            Self::TokensAccountingError(e) => e.check_intermittency(),
            Self::TokensAccountingBlockUndoError(e) => e.check_intermittency(),
            Self::RewardDistributionError(e) => e.check_intermittency(),
            Self::CheckTransactionError(e) => e.check_intermittency(),

            Self::TxNumWrongInBlockOnConnect(_, _)
            | Self::TxNumWrongInBlockOnDisconnect(_, _)
            | Self::InvariantBrokenAlreadyUnspent
            | Self::MissingOutputOrSpent(_)
            | Self::MissingTxInputs
            | Self::MissingTxUndo(_)
            | Self::MissingBlockUndo(_)
            | Self::MissingBlockRewardUndo(_)
            | Self::MissingMempoolTxsUndo
            | Self::AttemptToPrintMoney(_, _)
            | Self::BlockRewardInputOutputMismatch(_, _)
            | Self::TxFeeTotalCalcFailed(_, _)
            | Self::SignatureVerificationFailed(_)
            | Self::BlockHeightArithmeticError
            | Self::BlockTimestampArithmeticError
            | Self::InvariantErrorHeaderCouldNotBeLoaded(_)
            | Self::InvariantErrorHeaderCouldNotBeLoadedFromHeight(_, _)
            | Self::BlockIndexCouldNotBeLoaded(_)
            | Self::FailedToAddAllFeesOfBlock(_)
            | Self::RewardAdditionError(_)
            | Self::TimeLockViolation(_)
            | Self::BurnAmountSumError(_)
            | Self::AttemptToSpendBurnedAmount
            | Self::SpendStakeError(_)
            | Self::StakerBalanceNotFound(_)
            | Self::PoolDataNotFound(_)
            | Self::PoolBalanceNotFound(_)
            | Self::UnexpectedPoolId(_, _)
            | Self::UndoFetchFailure
            | Self::TxVerifierStorage
            | Self::OutputTimelockError(_)
            | Self::NonceIsNotIncremental(_, _, _)
            | Self::MissingTransactionNonce(_)
            | Self::NotEnoughPledgeToCreateStakePool(_, _, _)
            | Self::AttemptToCreateStakePoolFromAccounts
            | Self::AttemptToCreateDelegationFromAccounts
            | Self::FailedToIncrementAccountNonce
            | Self::IOPolicyError(_, _)
            | Self::ConstrainedValueAccumulatorError(_, _)
            | Self::TotalFeeRequiredOverflow
            | Self::InsufficientCoinsFee(_, _)
            | Self::AttemptToSpendFrozenToken(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tx_verifier::TransactionVerifierStorageError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StatePersistenceError(e) => e.check_intermittency(),
            Self::TokensError(e) => e.check_intermittency(),
            Self::UtxoError(e) => e.check_intermittency(),
            Self::UtxoBlockUndoError(e) => e.check_intermittency(),
            Self::PoSAccountingError(e) => e.check_intermittency(),
            Self::AccountingBlockUndoError(e) => e.check_intermittency(),
            Self::TokensAccountingError(e) => e.check_intermittency(),
            Self::TokensAccountingBlockUndoError(e) => e.check_intermittency(),

            Self::GenBlockIndexRetrievalFailed(_)
            | Self::GetAncestorError(_)
            | Self::DuplicateBlockUndo(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for crate::detail::chainstateref::ReorgError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::OtherError(e) => e.check_intermittency(),
            Self::ConnectTipFailed(_, _) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tokens_accounting::BlockUndoError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::UndoAlreadyExists(_) | Self::MissingTxUndo(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tokens_accounting::Error {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::AccountingError(e) => e.check_intermittency(),
            Self::StorageWrite => Intermittency::UNKNOWN,

            Self::TokenAlreadyExists(_)
            | Self::TokenDataNotFound(_)
            | Self::TokenDataNotFoundOnReversal(_)
            | Self::CirculatingSupplyNotFound(_)
            | Self::MintExceedsSupplyLimit(_, _, _)
            | Self::AmountOverflow
            | Self::CannotMintFromLockedSupply(_)
            | Self::CannotMintFrozenToken(_)
            | Self::CannotUnmintFromLockedSupply(_)
            | Self::CannotUnmintFrozenToken(_)
            | Self::NotEnoughCirculatingSupplyToUnmint(_, _, _)
            | Self::SupplyIsAlreadyLocked(_)
            | Self::CannotLockNotLockableSupply(_)
            | Self::CannotLockFrozenToken(_)
            | Self::CannotUnlockNotLockedSupplyOnReversal(_)
            | Self::CannotUndoMintForLockedSupplyOnReversal(_)
            | Self::CannotUndoUnmintForLockedSupplyOnReversal(_)
            | Self::TokenIsAlreadyFrozen(_)
            | Self::CannotFreezeNotFreezableToken(_)
            | Self::CannotUnfreezeNotUnfreezableToken(_)
            | Self::CannotUnfreezeTokenThatIsNotFrozen(_)
            | Self::CannotUndoFreezeTokenThatIsNotFrozen(_)
            | Self::CannotUndoUnfreezeTokenThatIsFrozen(_)
            | Self::CannotChangeAuthorityForFrozenToken(_)
            | Self::CannotUndoChangeAuthorityForFrozenToken(_)
            | Self::ViewFail => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for pos_accounting::Error {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::AccountingError(e) => e.check_intermittency(),

            Self::InvariantErrorPoolBalanceAlreadyExists
            | Self::InvariantErrorPoolDataAlreadyExists
            | Self::AttemptedDecommissionNonexistingPoolBalance
            | Self::AttemptedDecommissionNonexistingPoolData
            | Self::DelegationCreationFailedPoolDoesNotExist
            | Self::DelegationDeletionFailedIdDoesNotExist
            | Self::DelegationDeletionFailedBalanceNonZero
            | Self::DelegationDeletionFailedPoolsShareNonZero
            | Self::DelegationDeletionFailedPoolStillExists
            | Self::InvariantErrorDelegationCreationFailedIdAlreadyExists
            | Self::DelegateToNonexistingId
            | Self::DelegateToNonexistingPool
            | Self::AdditionError
            | Self::SubError
            | Self::DelegationBalanceAdditionError
            | Self::DelegationBalanceSubtractionError
            | Self::PoolBalanceAdditionError
            | Self::PoolBalanceSubtractionError
            | Self::DelegationSharesAdditionError
            | Self::DelegationSharesSubtractionError
            | Self::InvariantErrorPoolCreationReversalFailedBalanceNotFound
            | Self::InvariantErrorPoolCreationReversalFailedDataNotFound
            | Self::InvariantErrorPoolCreationReversalFailedAmountChanged
            | Self::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists
            | Self::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists
            | Self::InvariantErrorDelegationIdUndoFailedNotFound
            | Self::InvariantErrorDelegationIdUndoFailedDataConflict
            | Self::InvariantErrorDelegationBalanceAdditionUndoError
            | Self::InvariantErrorPoolBalanceAdditionUndoError
            | Self::InvariantErrorDelegationSharesAdditionUndoError
            | Self::InvariantErrorDelegationShareNotFound
            | Self::PledgeValueToSignedError
            | Self::InvariantErrorDelegationUndoFailedDataNotFound(_)
            | Self::DuplicatesInDeltaAndUndo
            | Self::IncreaseStakerRewardsOfNonexistingPool
            | Self::StakerBalanceOverflow
            | Self::InvariantErrorIncreasePledgeUndoFailedPoolBalanceNotFound
            | Self::InvariantErrorIncreaseStakerRewardUndoFailedPoolBalanceNotFound
            | Self::ViewFail => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for accounting::Error {
    fn check_intermittency(&self) -> Intermittency {
        Intermittency::Final
    }
}

impl CheckIntermittency for pos_accounting::BlockUndoError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::UndoAlreadyExists(_)
            | Self::MissingTxUndo(_)
            | Self::UndoAlreadyExistsForReward => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tx_verifier::error::TokensError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),

            Self::IssueError(_, _)
            | Self::MultipleTokenIssuanceInTransaction(_)
            | Self::CoinOrTokenOverflow(_)
            | Self::InsufficientTokenFees(_)
            | Self::TransferZeroTokens(_, _)
            | Self::TokenIdCantBeCalculated
            | Self::TokensInBlockReward
            | Self::InvariantBrokenUndoIssuanceOnNonexistentToken(_)
            | Self::InvariantBrokenRegisterIssuanceWithDuplicateId(_)
            | Self::DeprecatedTokenOperationVersion(_, _) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tx_verifier::CheckTransactionError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::PropertyQueryError(e) => e.check_intermittency(),
            Self::TokensError(e) => e.check_intermittency(),

            Self::DuplicateInputInTransaction(_)
            | Self::InvalidWitnessCount(_)
            | Self::EmptyInputsInTransaction(_)
            | Self::NoSignatureDataSizeTooLarge(_, _, _)
            | Self::NoSignatureDataNotAllowed(_)
            | Self::DataDepositMaxSizeExceeded(_, _, _)
            | Self::TxSizeTooLarge(_, _, _) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tx_verifier::transaction_verifier::RewardDistributionError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::PoSAccountingError(e) => e.check_intermittency(),

            Self::InvariantPoolBalanceIsZero(_)
            | Self::InvariantStakerBalanceGreaterThanPoolBalance(_, _, _)
            | Self::RewardAdditionError(_)
            | Self::TotalDelegationBalanceZero(_)
            | Self::PoolDataNotFound(_)
            | Self::PoolBalanceNotFound(_)
            | Self::StakerRewardCalculationFailed(_, _)
            | Self::StakerRewardCannotExceedTotalReward(_, _, _, _)
            | Self::DistributedDelegationsRewardExceedTotal(_, _, _, _)
            | Self::DelegationRewardOverflow(_, _, _, _)
            | Self::DelegationsRewardSumFailed(_, _)
            | Self::StakerRewardOverflow(_, _, _, _) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for signature_destination_getter::SignatureDestinationGetterError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::UtxoViewError(e) => e.check_intermittency(),
            Self::SigVerifyPoSAccountingError(e) => e.check_intermittency(),
            Self::SigVerifyTokensAccountingError(e) => e.check_intermittency(),

            Self::SpendingOutputInBlockReward
            | Self::SpendingFromAccountInBlockReward
            | Self::SigVerifyOfNotSpendableOutput
            | Self::PoolDataNotFound(_)
            | Self::DelegationDataNotFound(_)
            | Self::TokenDataNotFound(_)
            | Self::UtxoOutputNotFound(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for utxo::Error {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageWrite => Intermittency::UNKNOWN,

            Self::OverwritingUtxo
            | Self::FreshUtxoAlreadyExists
            | Self::UtxoAlreadySpent(_)
            | Self::NoUtxoFound
            | Self::NoBlockchainHeightFound
            | Self::MissingBlockRewardUndo(_)
            | Self::InvalidBlockRewardOutputType(_)
            | Self::TxInputAndUndoMismatch(_)
            | Self::ViewRead => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for utxo::UtxosBlockUndoError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::UndoAlreadyExists(_)
            | Self::UndoAlreadyExistsForReward
            | Self::TxUndoWithDependency(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for crate::detail::chainstateref::EpochSealError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::PoSAccountingError(e) => e.check_intermittency(),
            Self::SpendStakeError(e) => e.check_intermittency(),

            Self::RandomnessError(_) | Self::PoolDataNotFound(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for tx_verifier::error::SpendStakeError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::ConsensusPoSError(e) => e.check_intermittency(),

            Self::NoBlockRewardOutputs
            | Self::MultipleBlockRewardOutputs
            | Self::InvalidBlockRewardOutputType
            | Self::StakePoolDataMismatch
            | Self::StakePoolIdMismatch(_, _) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for crate::CheckBlockTransactionsError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::CheckTransactionError(e) => e.check_intermittency(),

            Self::DuplicateInputInBlock(_) => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for consensus::ConsensusVerificationError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::PrevBlockLoadError(_, _, e) => e.check_intermittency(),
            Self::PoWError(e) => e.check_intermittency(),
            Self::PoSError(e) => e.check_intermittency(),

            Self::PrevBlockNotFound(_, _)
            | Self::ConsensusTypeMismatch(_)
            | Self::UnsupportedConsensusType => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for consensus::ConsensusPoWError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::PrevBlockLoadError(_, e) | Self::AncestorAtHeightNotFound(_, _, e) => {
                e.check_intermittency()
            }

            Self::InvalidPoW(_)
            | Self::PrevBlockNotFound(_)
            | Self::NoPowDataInPreviousBlock
            | Self::DecodingBitsFailed(_)
            | Self::PreviousBitsDecodingFailed(_)
            | Self::InvalidTargetBits(_, _)
            | Self::PoSInputDataProvided
            | Self::NoInputDataProvided => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for consensus::ConsensusPoSError {
    fn check_intermittency(&self) -> Intermittency {
        match self {
            Self::StorageError(e) => e.check_intermittency(),
            Self::PropertyQueryError(e) => e.check_intermittency(),
            Self::ChainstateError(e) => e.check_intermittency(),
            Self::PoSAccountingError(e) => e.check_intermittency(),

            Self::StakeKernelHashTooHigh
            | Self::NoEpochData
            | Self::TimestampViolation(_, _)
            | Self::NoKernel
            | Self::MissingKernelUtxo
            | Self::KernelOutpointMustBeUtxo
            | Self::MultipleKernels
            | Self::BitsToTargetConversionFailed(_)
            | Self::PrevBlockIndexNotFound(_)
            | Self::PoolBalanceNotFound(_)
            | Self::PoolDataNotFound(_)
            | Self::RandomnessError(_)
            | Self::InvalidTarget(_)
            | Self::DecodingBitsFailed(_)
            | Self::TargetConversionError(_)
            | Self::NotEnoughTimestampsToAverage
            | Self::InvalidTargetBlockTime
            | Self::TimestampOverflow
            | Self::InvariantBrokenNotMonotonicBlockTime
            | Self::EmptyTimespan
            | Self::NoInputDataProvided
            | Self::PoWInputDataProvided
            | Self::FailedReadingBlock(_)
            | Self::FutureTimestampInThePast
            | Self::FailedToFetchUtxo
            | Self::BlockSignatureError(_)
            | Self::FailedToSignBlockHeader
            | Self::FailedToSignKernel
            | Self::PoSBlockTimeStrictOrderInvalid(_)
            | Self::FiniteTotalSupplyIsRequired
            | Self::UnsupportedConsensusVersion
            | Self::EffectivePoolBalanceError(_)
            | Self::FailedToCalculateCappedBalance => Intermittency::Final,
        }
    }
}

impl CheckIntermittency for consensus::ChainstateError {
    fn check_intermittency(&self) -> Intermittency {
        Intermittency::UNKNOWN
    }
}

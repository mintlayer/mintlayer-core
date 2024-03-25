// Copyright (c) 2021-2024 RBB S.r.l
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

use chainstate_types::{
    pos_randomness::PoSRandomnessError, storage_result, GetAncestorError, PropertyQueryError,
};
use common::{
    chain::{block::block_body::BlockMerkleTreeError, signature::DestinationSigError},
    UintConversionError,
};
use consensus::{
    BlockSignatureError, ConsensusPoSError, ConsensusPoWError, ConsensusVerificationError,
    EffectivePoolBalanceError,
};
use tx_verifier::{
    error::{ConnectTransactionError, SpendStakeError, TokensError},
    timelock_check,
    transaction_verifier::{
        signature_destination_getter::SignatureDestinationGetterError, RewardDistributionError,
    },
    CheckTransactionError, TransactionVerifierStorageError,
};
use utxo::UtxosBlockUndoError;

use crate::{BlockError, CheckBlockError, CheckBlockTransactionsError, OrphanCheckError};

use super::{
    block_invalidation::BestChainCandidatesError, chainstateref::EpochSealError, BlockSizeError,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BlockProcessingErrorClass {
    /// General error - the operation failed  due to storage issues, invariant violations etc.
    General,
    /// This error type signifies that the block is definitely bad.
    BadBlock,
    /// This error type signifies that the block is bad at this moment, but might become ok later.
    TemporarilyBadBlock,
}

impl BlockProcessingErrorClass {
    pub fn block_should_be_invalidated(&self) -> bool {
        match self {
            BlockProcessingErrorClass::General | BlockProcessingErrorClass::TemporarilyBadBlock => {
                false
            }
            BlockProcessingErrorClass::BadBlock => true,
        }
    }
}

// Note:
// 1) For some errors it's not always clear whether they denote an invariant violation or a
// problem with the block itself.
// But misclassification of such an error is not a critical issue:
// a) If an invariant violation happened, the local copy of the chainstate is likely to be broken
// anyway, so marking a possibly ok block as bad won't do much additional harm.
// b) Returning General for an objectively bad block (and therefore not marking it as invalid
// in the block index) is not a huge problem either, because the block will be rejected anyway
// on all future attempts to add it.
// 2) Technically the same can be said about storage errors too - they'll "normally" happen if
// the user's storage device is faulty; though we should try to handle such situations gracefully,
// occasional failure to do so is not critical.
// 3) The errors that should be treated carefully are those that can happen during normal
// cause of operation and that don't represent a 100% invalid block (e.g. BlockFromTheFuture).

pub trait BlockProcessingErrorClassification {
    fn classify(&self) -> BlockProcessingErrorClass;
}

impl BlockProcessingErrorClassification for BlockError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            BlockError::InvariantErrorFailedToFindNewChainPath(_, _, _)
            | BlockError::InvariantErrorInvalidTip(_)
            | BlockError::InvariantErrorAttemptToConnectInvalidBlock(_)
            | BlockError::InvariantErrorDisconnectedHeaders
            | BlockError::DbCommitError(_, _, _)
            | BlockError::BlockAlreadyExists(_)
            | BlockError::BlockIndexAlreadyExists(_)
            | BlockError::BlockAlreadyProcessed(_)
            | BlockError::BlockDataMissingForValidBlockIndex(_)
            // These contain an error inside, but they are meant to denote storage/invariant
            // problems in any case, so we don't delegate to inner error's `classify` here.
            | BlockError::BestBlockIdQueryError(_)
            | BlockError::BestBlockIndexQueryError(_)
            | BlockError::BlockIndexQueryError(_, _)
            | BlockError::IsBlockInMainChainQueryError(_, _)
            | BlockError::MinHeightForReorgQueryError(_) => BlockProcessingErrorClass::General,

            BlockError::PrevBlockNotFoundForNewBlock(_) => {
                BlockProcessingErrorClass::TemporarilyBadBlock
            }

            // It's not clear what should be returned here - from the one side, the block is definitely
            // bad, from the other side any "bad" status handling has already been done for the block
            // during the previous attempt.
            // Currently though, it doesn't matter whether we return "BadBlock" or "General" here.
            BlockError::InvalidBlockAlreadyProcessed(_) => BlockProcessingErrorClass::BadBlock,

            BlockError::BlockProofCalculationError(_) => BlockProcessingErrorClass::BadBlock,

            BlockError::TransactionVerifierError(err) => err.classify(),
            BlockError::PoSAccountingError(err) => err.classify(),
            BlockError::EpochSealError(err) => err.classify(),

            BlockError::BestChainCandidatesAccessorError(err) => err.classify(),
            BlockError::TokensAccountingError(err) => err.classify(),
            BlockError::StorageError(err) => err.classify(),
            BlockError::OrphanCheckFailed(err) => err.classify(),
            BlockError::CheckBlockFailed(err) => err.classify(),
            BlockError::StateUpdateFailed(err) => err.classify(),
            BlockError::PropertyQueryError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for BestChainCandidatesError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            BestChainCandidatesError::PropertyQueryError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for OrphanCheckError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            OrphanCheckError::LocalOrphan => BlockProcessingErrorClass::TemporarilyBadBlock,

            OrphanCheckError::StorageError(err) => err.classify(),
            OrphanCheckError::PropertyQueryError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for CheckBlockError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            CheckBlockError::MerkleRootMismatch
            | CheckBlockError::ParentBlockMissing { .. }
            | CheckBlockError::BlockNotFoundDuringInMemoryReorg(_)
            | CheckBlockError::BlockTimeOrderInvalid(_, _)
            | CheckBlockError::InvalidBlockRewardOutputType(_)
            | CheckBlockError::CheckpointMismatch(_, _)
            | CheckBlockError::ParentCheckpointMismatch(_, _, _)
            | CheckBlockError::AttemptedToAddBlockBeforeReorgLimit(_, _, _)
            | CheckBlockError::InvalidParent { .. } => BlockProcessingErrorClass::BadBlock,

            CheckBlockError::BlockFromTheFuture(_) => {
                BlockProcessingErrorClass::TemporarilyBadBlock
            }

            CheckBlockError::StorageError(err) => err.classify(),
            CheckBlockError::PropertyQueryError(err) => err.classify(),
            CheckBlockError::MerkleRootCalculationFailed(_, err) => err.classify(),
            CheckBlockError::StateUpdateFailed(err) => err.classify(),
            CheckBlockError::BlockSizeError(err) => err.classify(),
            CheckBlockError::BlockRewardMaturityError(err) => err.classify(),
            CheckBlockError::TransactionVerifierError(err) => err.classify(),
            CheckBlockError::EpochSealError(err) => err.classify(),
            CheckBlockError::CheckTransactionFailed(err) => err.classify(),
            CheckBlockError::ConsensusVerificationFailed(err) => err.classify(),
            CheckBlockError::GetAncestorError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for BlockMerkleTreeError {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for BlockSizeError {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for EpochSealError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            // Use "General" for consistency with the zero ban score.
            EpochSealError::PoolDataNotFound(_) => BlockProcessingErrorClass::General,

            EpochSealError::StorageError(err) => err.classify(),
            EpochSealError::PoSAccountingError(err) => err.classify(),
            EpochSealError::SpendStakeError(err) => err.classify(),
            EpochSealError::RandomnessError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for CheckBlockTransactionsError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            CheckBlockTransactionsError::DuplicateInputInBlock(_) => {
                BlockProcessingErrorClass::BadBlock
            }

            CheckBlockTransactionsError::CheckTransactionError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for ConsensusVerificationError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            ConsensusVerificationError::PrevBlockNotFound(_, _)
            | ConsensusVerificationError::ConsensusTypeMismatch(_)
            | ConsensusVerificationError::UnsupportedConsensusType => {
                BlockProcessingErrorClass::BadBlock
            }

            ConsensusVerificationError::PrevBlockLoadError(_, _, err) => err.classify(),
            ConsensusVerificationError::PoWError(err) => err.classify(),
            ConsensusVerificationError::PoSError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for ConnectTransactionError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            // Use "General" for consistency with the zero ban score.
            ConnectTransactionError::TxNumWrongInBlockOnDisconnect(_, _)
            | ConnectTransactionError::InvariantBrokenAlreadyUnspent
            | ConnectTransactionError::MissingBlockUndo(_)
            | ConnectTransactionError::MissingBlockRewardUndo(_)
            | ConnectTransactionError::MissingTxUndo(_)
            | ConnectTransactionError::MissingMempoolTxsUndo
            | ConnectTransactionError::StakerBalanceNotFound(_)
            | ConnectTransactionError::PoolDataNotFound(_)
            | ConnectTransactionError::UndoFetchFailure
            | ConnectTransactionError::TxVerifierStorage
            | ConnectTransactionError::FailedToIncrementAccountNonce => {
                BlockProcessingErrorClass::General
            }

            ConnectTransactionError::TxNumWrongInBlockOnConnect(_, _)
            | ConnectTransactionError::MissingOutputOrSpent(_)
            | ConnectTransactionError::MissingTxInputs
            | ConnectTransactionError::AttemptToPrintMoney(_, _)
            | ConnectTransactionError::BlockRewardInputOutputMismatch(_, _)
            | ConnectTransactionError::TxFeeTotalCalcFailed(_, _)
            | ConnectTransactionError::BlockHeightArithmeticError
            | ConnectTransactionError::BlockTimestampArithmeticError
            | ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoaded(_)
            | ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(_, _)
            | ConnectTransactionError::BlockIndexCouldNotBeLoaded(_)
            | ConnectTransactionError::FailedToAddAllFeesOfBlock(_)
            | ConnectTransactionError::RewardAdditionError(_)
            | ConnectTransactionError::TimeLockViolation(_)
            | ConnectTransactionError::BurnAmountSumError(_)
            | ConnectTransactionError::AttemptToSpendBurnedAmount
            | ConnectTransactionError::PoolBalanceNotFound(_)
            | ConnectTransactionError::UnexpectedPoolId(_, _)
            | ConnectTransactionError::NonceIsNotIncremental(_, _, _)
            | ConnectTransactionError::MissingTransactionNonce(_)
            | ConnectTransactionError::NotEnoughPledgeToCreateStakePool(_, _, _)
            | ConnectTransactionError::AttemptToCreateStakePoolFromAccounts
            | ConnectTransactionError::AttemptToCreateDelegationFromAccounts
            | ConnectTransactionError::IOPolicyError(_, _)
            | ConnectTransactionError::TotalFeeRequiredOverflow
            | ConnectTransactionError::InsufficientCoinsFee(_, _)
            | ConnectTransactionError::AttemptToSpendFrozenToken(_) => {
                BlockProcessingErrorClass::BadBlock
            }

            ConnectTransactionError::StorageError(err) => err.classify(),
            ConnectTransactionError::SignatureVerificationFailed(err) => err.classify(),
            ConnectTransactionError::UtxoError(err) => err.classify(),
            ConnectTransactionError::TokensError(err) => err.classify(),
            ConnectTransactionError::TransactionVerifierError(err) => err.classify(),
            ConnectTransactionError::UtxoBlockUndoError(err) => err.classify(),
            ConnectTransactionError::AccountingBlockUndoError(err) => err.classify(),
            ConnectTransactionError::DestinationRetrievalError(err) => err.classify(),
            ConnectTransactionError::OutputTimelockError(err) => err.classify(),
            ConnectTransactionError::SpendStakeError(err) => err.classify(),
            ConnectTransactionError::TokensAccountingError(err) => err.classify(),
            ConnectTransactionError::TokensAccountingBlockUndoError(err) => err.classify(),
            ConnectTransactionError::RewardDistributionError(err) => err.classify(),
            ConnectTransactionError::CheckTransactionError(err) => err.classify(),
            ConnectTransactionError::PoSAccountingError(err) => err.classify(),
            ConnectTransactionError::ConstrainedValueAccumulatorError(err, _) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for storage_result::Error {
    fn classify(&self) -> BlockProcessingErrorClass {
        BlockProcessingErrorClass::General
    }
}

impl BlockProcessingErrorClassification for PropertyQueryError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            PropertyQueryError::BestBlockIndexNotFound
            | PropertyQueryError::BlockNotFound(_)
            | PropertyQueryError::BlockIndexNotFound(_)
            | PropertyQueryError::PrevBlockIndexNotFound { .. }
            | PropertyQueryError::BlockForHeightNotFound(_)
            | PropertyQueryError::GenesisHeaderRequested
            | PropertyQueryError::InvalidStartingBlockHeightForMainchainBlocks(_)
            | PropertyQueryError::InvalidBlockHeightRange { .. } => {
                BlockProcessingErrorClass::General
            }
            // Note: these errors are strange - sometimes they don't look like General, judging
            // by the code that uses them. But other times some of them seem to just wrap storage
            // errors.
            // For now, since their p2p ban score is 0, let's consider them General.
            PropertyQueryError::StakePoolDataNotFound(_)
            | PropertyQueryError::StakerBalanceOverflow(_)
            | PropertyQueryError::PoolBalanceNotFound(_) => BlockProcessingErrorClass::General,

            PropertyQueryError::StorageError(err) => err.classify(),
            PropertyQueryError::GetAncestorError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for DestinationSigError {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for utxo::Error {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for TokensError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            TokensError::StorageError(_) => BlockProcessingErrorClass::General,

            TokensError::IssueError(_, _)
            | TokensError::MultipleTokenIssuanceInTransaction(_)
            | TokensError::CoinOrTokenOverflow(_)
            | TokensError::InsufficientTokenFees(_)
            | TokensError::TransferZeroTokens(_, _)
            | TokensError::TokenIdCantBeCalculated
            | TokensError::TokensInBlockReward
            | TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(_)
            | TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(_)
            | TokensError::DeprecatedTokenOperationVersion(_, _) => {
                BlockProcessingErrorClass::BadBlock
            }
        }
    }
}

impl BlockProcessingErrorClassification for TransactionVerifierStorageError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            TransactionVerifierStorageError::GenBlockIndexRetrievalFailed(_)
            | TransactionVerifierStorageError::DuplicateBlockUndo(_) => {
                BlockProcessingErrorClass::BadBlock
            }

            TransactionVerifierStorageError::StatePersistenceError(err) => err.classify(),
            TransactionVerifierStorageError::GetAncestorError(err) => err.classify(),
            TransactionVerifierStorageError::TokensError(err) => err.classify(),
            TransactionVerifierStorageError::UtxoError(err) => err.classify(),
            TransactionVerifierStorageError::UtxoBlockUndoError(err) => err.classify(),
            TransactionVerifierStorageError::PoSAccountingError(err) => err.classify(),
            TransactionVerifierStorageError::AccountingBlockUndoError(err) => err.classify(),
            TransactionVerifierStorageError::TokensAccountingError(err) => err.classify(),
            TransactionVerifierStorageError::TokensAccountingBlockUndoError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for GetAncestorError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            // Use "General" for consistency with the zero ban score.
            GetAncestorError::PrevBlockIndexNotFound(_)
            | GetAncestorError::StartingPointNotFound(_)
            // Note: this one is more like an invariant violation, despite its ban score being 100.
            | GetAncestorError::InvalidAncestorHeight { .. }
            => BlockProcessingErrorClass::General,

            GetAncestorError::StorageError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for UtxosBlockUndoError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            UtxosBlockUndoError::UndoAlreadyExists(_)
            | UtxosBlockUndoError::UndoAlreadyExistsForReward
            | UtxosBlockUndoError::TxUndoWithDependency(_) => BlockProcessingErrorClass::BadBlock,
        }
    }
}

impl BlockProcessingErrorClassification for pos_accounting::BlockUndoError {
    fn classify(&self) -> BlockProcessingErrorClass {
        use pos_accounting::BlockUndoError;

        match self {
            BlockUndoError::UndoAlreadyExists(_)
            | BlockUndoError::MissingTxUndo(_)
            | BlockUndoError::UndoAlreadyExistsForReward => BlockProcessingErrorClass::BadBlock,
        }
    }
}

impl BlockProcessingErrorClassification for SignatureDestinationGetterError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            SignatureDestinationGetterError::SpendingOutputInBlockReward
            | SignatureDestinationGetterError::SpendingFromAccountInBlockReward
            | SignatureDestinationGetterError::SigVerifyOfNotSpendableOutput
            | SignatureDestinationGetterError::PoolDataNotFound(_)
            | SignatureDestinationGetterError::DelegationDataNotFound(_)
            | SignatureDestinationGetterError::TokenDataNotFound(_)
            | SignatureDestinationGetterError::UtxoOutputNotFound(_) => {
                BlockProcessingErrorClass::BadBlock
            }

            SignatureDestinationGetterError::UtxoViewError(err) => err.classify(),
            SignatureDestinationGetterError::SigVerifyPoSAccountingError(err) => err.classify(),
            SignatureDestinationGetterError::SigVerifyTokensAccountingError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for timelock_check::OutputMaturityError {
    fn classify(&self) -> BlockProcessingErrorClass {
        use timelock_check::OutputMaturityError;

        match self {
            OutputMaturityError::InvalidOutputMaturitySettingType(_)
            | OutputMaturityError::InvalidOutputMaturityDistance(_, _, _) => {
                BlockProcessingErrorClass::BadBlock
            }
        }
    }
}

impl BlockProcessingErrorClassification for SpendStakeError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            SpendStakeError::NoBlockRewardOutputs
            | SpendStakeError::MultipleBlockRewardOutputs
            | SpendStakeError::InvalidBlockRewardOutputType
            | SpendStakeError::StakePoolDataMismatch
            | SpendStakeError::StakePoolIdMismatch(_, _) => BlockProcessingErrorClass::BadBlock,

            SpendStakeError::ConsensusPoSError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for ConsensusPoWError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            // Use "General" for consistency with the zero ban score.
            ConsensusPoWError::PreviousBitsDecodingFailed(_) => BlockProcessingErrorClass::General,

            ConsensusPoWError::InvalidPoW(_)
            | ConsensusPoWError::PrevBlockNotFound(_)
            | ConsensusPoWError::NoPowDataInPreviousBlock
            | ConsensusPoWError::DecodingBitsFailed(_)
            | ConsensusPoWError::InvalidTargetBits(_, _)
            | ConsensusPoWError::PoSInputDataProvided
            | ConsensusPoWError::NoInputDataProvided => BlockProcessingErrorClass::BadBlock,

            ConsensusPoWError::PrevBlockLoadError(_, err) => err.classify(),
            ConsensusPoWError::AncestorAtHeightNotFound(_, _, err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for ConsensusPoSError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            // Use "General" for consistency with the zero ban score.
            ConsensusPoSError::NoEpochData
            | ConsensusPoSError::PrevBlockIndexNotFound(_)
            | ConsensusPoSError::PoolDataNotFound(_)
            | ConsensusPoSError::FailedToFetchUtxo
            | ConsensusPoSError::FailedToSignBlockHeader
            | ConsensusPoSError::FailedReadingBlock(_)
            | ConsensusPoSError::FutureTimestampInThePast
            | ConsensusPoSError::FailedToSignKernel => BlockProcessingErrorClass::General,

            ConsensusPoSError::StakeKernelHashTooHigh
            | ConsensusPoSError::TimestampViolation(_, _)
            | ConsensusPoSError::NoKernel
            | ConsensusPoSError::MissingKernelUtxo
            | ConsensusPoSError::KernelOutpointMustBeUtxo
            | ConsensusPoSError::MultipleKernels
            | ConsensusPoSError::BitsToTargetConversionFailed(_)
            | ConsensusPoSError::PoolBalanceNotFound(_)
            | ConsensusPoSError::InvalidTarget(_)
            | ConsensusPoSError::DecodingBitsFailed(_)
            | ConsensusPoSError::NotEnoughTimestampsToAverage
            | ConsensusPoSError::InvalidTargetBlockTime
            | ConsensusPoSError::TimestampOverflow
            | ConsensusPoSError::InvariantBrokenNotMonotonicBlockTime
            | ConsensusPoSError::EmptyTimespan
            | ConsensusPoSError::NoInputDataProvided
            | ConsensusPoSError::PoWInputDataProvided
            | ConsensusPoSError::PoSBlockTimeStrictOrderInvalid(_)
            | ConsensusPoSError::FiniteTotalSupplyIsRequired
            | ConsensusPoSError::UnsupportedConsensusVersion
            | ConsensusPoSError::FailedToCalculateCappedBalance => {
                BlockProcessingErrorClass::BadBlock
            }

            ConsensusPoSError::TargetConversionError(err) => match err {
                UintConversionError::ConversionOverflow => BlockProcessingErrorClass::BadBlock,
            },

            ConsensusPoSError::StorageError(err) => err.classify(),
            ConsensusPoSError::PropertyQueryError(err) => err.classify(),
            ConsensusPoSError::ChainstateError(err) => err.classify(),
            ConsensusPoSError::PoSAccountingError(err) => err.classify(),
            ConsensusPoSError::RandomnessError(err) => err.classify(),
            ConsensusPoSError::BlockSignatureError(err) => err.classify(),
            ConsensusPoSError::EffectivePoolBalanceError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for consensus::ChainstateError {
    fn classify(&self) -> BlockProcessingErrorClass {
        use consensus::ChainstateError;

        match self {
            // These all represent a general chainstate failure.
            // TODO: it's better to delegate to the inner error anyway.
            ChainstateError::FailedToObtainEpochData(_, _err)
            | ChainstateError::StakePoolDataReadError(_, _err)
            | ChainstateError::PoolBalanceReadError(_, _err) => BlockProcessingErrorClass::General,
        }
    }
}

impl BlockProcessingErrorClassification for PoSRandomnessError {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for BlockSignatureError {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for EffectivePoolBalanceError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            EffectivePoolBalanceError::ArithmeticError
            | EffectivePoolBalanceError::FinalSupplyZero
            | EffectivePoolBalanceError::PoolBalanceGreaterThanSupply(_, _)
            | EffectivePoolBalanceError::PoolPledgeGreaterThanBalance(_, _)
            | EffectivePoolBalanceError::AdjustmentMustFitIntoAmount => {
                BlockProcessingErrorClass::BadBlock
            }
        }
    }
}

impl BlockProcessingErrorClassification for tokens_accounting::Error {
    fn classify(&self) -> BlockProcessingErrorClass {
        use tokens_accounting::Error;

        match self {
            // Use "General" for consistency with the zero ban score.
            Error::ViewFail | Error::StorageWrite => BlockProcessingErrorClass::General,

            Error::TokenAlreadyExists(_)
            | Error::TokenDataNotFound(_)
            | Error::TokenDataNotFoundOnReversal(_)
            | Error::CirculatingSupplyNotFound(_)
            | Error::MintExceedsSupplyLimit(_, _, _)
            | Error::AmountOverflow
            | Error::CannotMintFromLockedSupply(_)
            | Error::CannotMintFrozenToken(_)
            | Error::CannotUnmintFromLockedSupply(_)
            | Error::CannotUnmintFrozenToken(_)
            | Error::NotEnoughCirculatingSupplyToUnmint(_, _, _)
            | Error::SupplyIsAlreadyLocked(_)
            | Error::CannotLockNotLockableSupply(_)
            | Error::CannotLockFrozenToken(_)
            | Error::CannotUnlockNotLockedSupplyOnReversal(_)
            | Error::CannotUndoMintForLockedSupplyOnReversal(_)
            | Error::CannotUndoUnmintForLockedSupplyOnReversal(_)
            | Error::TokenIsAlreadyFrozen(_)
            | Error::CannotFreezeNotFreezableToken(_)
            | Error::CannotUnfreezeNotUnfreezableToken(_)
            | Error::CannotUnfreezeTokenThatIsNotFrozen(_)
            | Error::CannotUndoFreezeTokenThatIsNotFrozen(_)
            | Error::CannotUndoUnfreezeTokenThatIsFrozen(_)
            | Error::CannotChangeAuthorityForFrozenToken(_)
            | Error::CannotUndoChangeAuthorityForFrozenToken(_) => {
                BlockProcessingErrorClass::BadBlock
            }

            Error::StorageError(err) => err.classify(),
            Error::AccountingError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for accounting::Error {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for tokens_accounting::BlockUndoError {
    fn classify(&self) -> BlockProcessingErrorClass {
        // Nothing other than BadBlock here.
        // TODO: should we descend into inner errors just in case?
        BlockProcessingErrorClass::BadBlock
    }
}

impl BlockProcessingErrorClassification for RewardDistributionError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            // Use "General" for consistency with the zero ban score.
            RewardDistributionError::PoolDataNotFound(_)
            | RewardDistributionError::PoolBalanceNotFound(_) => BlockProcessingErrorClass::General,

            RewardDistributionError::InvariantPoolBalanceIsZero(_)
            | RewardDistributionError::InvariantStakerBalanceGreaterThanPoolBalance(_, _, _)
            | RewardDistributionError::RewardAdditionError(_)
            | RewardDistributionError::TotalDelegationBalanceZero(_)
            | RewardDistributionError::StakerRewardCalculationFailed(_, _)
            | RewardDistributionError::StakerRewardCannotExceedTotalReward(_, _, _, _)
            | RewardDistributionError::DistributedDelegationsRewardExceedTotal(_, _, _, _)
            | RewardDistributionError::DelegationRewardOverflow(_, _, _, _)
            | RewardDistributionError::DelegationsRewardSumFailed(_, _)
            | RewardDistributionError::StakerRewardOverflow(_, _, _, _) => {
                BlockProcessingErrorClass::BadBlock
            }

            RewardDistributionError::PoSAccountingError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for CheckTransactionError {
    fn classify(&self) -> BlockProcessingErrorClass {
        match self {
            CheckTransactionError::DuplicateInputInTransaction(_)
            | CheckTransactionError::InvalidWitnessCount(_)
            | CheckTransactionError::EmptyInputsInTransaction(_)
            | CheckTransactionError::NoSignatureDataSizeTooLarge(_, _, _)
            | CheckTransactionError::NoSignatureDataNotAllowed(_)
            | CheckTransactionError::DataDepositMaxSizeExceeded(_, _, _)
            | CheckTransactionError::TxSizeTooLarge(_, _, _) => BlockProcessingErrorClass::BadBlock,

            CheckTransactionError::PropertyQueryError(err) => err.classify(),
            CheckTransactionError::TokensError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for pos_accounting::Error {
    fn classify(&self) -> BlockProcessingErrorClass {
        use pos_accounting::Error;

        match self {
            // Use "General" for consistency with the zero ban score.
            Error::ViewFail => BlockProcessingErrorClass::General,

            Error::InvariantErrorPoolBalanceAlreadyExists
            | Error::InvariantErrorPoolDataAlreadyExists
            | Error::AttemptedDecommissionNonexistingPoolBalance
            | Error::AttemptedDecommissionNonexistingPoolData
            | Error::DelegationCreationFailedPoolDoesNotExist
            | Error::DelegationDeletionFailedIdDoesNotExist
            | Error::DelegationDeletionFailedBalanceNonZero
            | Error::DelegationDeletionFailedPoolsShareNonZero
            | Error::DelegationDeletionFailedPoolStillExists
            | Error::InvariantErrorDelegationCreationFailedIdAlreadyExists
            | Error::DelegateToNonexistingId
            | Error::DelegateToNonexistingPool
            | Error::AdditionError
            | Error::SubError
            | Error::DelegationBalanceAdditionError
            | Error::DelegationBalanceSubtractionError
            | Error::PoolBalanceAdditionError
            | Error::PoolBalanceSubtractionError
            | Error::DelegationSharesAdditionError
            | Error::DelegationSharesSubtractionError
            | Error::InvariantErrorPoolCreationReversalFailedBalanceNotFound
            | Error::InvariantErrorPoolCreationReversalFailedDataNotFound
            | Error::InvariantErrorPoolCreationReversalFailedAmountChanged
            | Error::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists
            | Error::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists
            | Error::InvariantErrorDelegationIdUndoFailedNotFound
            | Error::InvariantErrorDelegationIdUndoFailedDataConflict
            | Error::InvariantErrorDelegationBalanceAdditionUndoError
            | Error::InvariantErrorPoolBalanceAdditionUndoError
            | Error::InvariantErrorDelegationSharesAdditionUndoError
            | Error::InvariantErrorDelegationShareNotFound
            | Error::PledgeValueToSignedError
            | Error::InvariantErrorDelegationUndoFailedDataNotFound(_)
            | Error::DuplicatesInDeltaAndUndo
            | Error::IncreaseStakerRewardsOfNonexistingPool
            | Error::StakerBalanceOverflow
            | Error::InvariantErrorIncreasePledgeUndoFailedPoolBalanceNotFound
            | Error::InvariantErrorIncreaseStakerRewardUndoFailedPoolBalanceNotFound => {
                BlockProcessingErrorClass::BadBlock
            }

            Error::StorageError(err) => err.classify(),
            Error::AccountingError(err) => err.classify(),
        }
    }
}

impl BlockProcessingErrorClassification for constraints_value_accumulator::Error {
    fn classify(&self) -> BlockProcessingErrorClass {
        use constraints_value_accumulator::Error;

        match self {
            // Use "General" for consistency with the zero ban score.
            Error::DelegationBalanceNotFound(_) | Error::AccountBalanceNotFound(_) => {
                BlockProcessingErrorClass::General
            }

            Error::AmountOverflow
            | Error::CoinOrTokenOverflow(_)
            | Error::AttemptToPrintMoney(_)
            | Error::AttemptToPrintMoneyOrViolateTimelockConstraints(_)
            | Error::AttemptToViolateFeeRequirements
            | Error::InputsAndInputsUtxosLengthMismatch(_, _)
            | Error::MissingOutputOrSpent(_)
            | Error::PledgeAmountNotFound(_)
            | Error::SpendingNonSpendableOutput(_)
            | Error::NegativeAccountBalance(_) => BlockProcessingErrorClass::BadBlock,

            Error::PoSAccountingError(err) => err.classify(),
        }
    }
}
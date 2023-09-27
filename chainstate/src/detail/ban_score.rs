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
        signature_destination_getter::SignatureDestinationGetterError, IOPolicyError,
    },
};

use super::{
    chainstateref::EpochSealError,
    transaction_verifier::{
        error::{ConnectTransactionError, TokensError},
        storage::TransactionVerifierStorageError,
    },
    BlockSizeError, CheckBlockError, CheckBlockTransactionsError, OrphanCheckError, TxIndexError,
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
            BlockError::BlockAlreadyProcessed(_) => 0,
            BlockError::InvalidBlockAlreadyProcessed(_) => 100,
            BlockError::DbCommitError(_, _, _) => 0,
            BlockError::BlockProofCalculationError(_) => 100,
            BlockError::TransactionVerifierError(err) => err.ban_score(),
            BlockError::TxIndexConfigError => 0,
            BlockError::TxIndexConstructionError(_) => 100,
            BlockError::PoSAccountingError(err) => err.ban_score(),
            BlockError::EpochSealError(err) => err.ban_score(),
            BlockError::BlockDataMissingForValidBlockIndex(_) => 0,
            BlockError::BestChainCandidatesAccessorError(_) => 0,

            BlockError::BestBlockIdQueryError(_) => 0,
            BlockError::BestBlockIndexQueryError(_) => 0,
            BlockError::BlockIndexQueryError(_, _) => 0,
            BlockError::IsBlockInMainChainQueryError(_, _) => 0,
            BlockError::MinHeightForReorgQueryError(_) => 0,

            BlockError::InvariantErrorFailedToFindNewChainPath(_, _, _) => 0,
            BlockError::InvariantErrorInvalidTip(_) => 0,
            BlockError::InvariantErrorAttemptToConnectInvalidBlock(_) => 0,
            BlockError::TokensAccountingError(err) => err.ban_score(),
        }
    }
}

impl BanScore for OrphanCheckError {
    fn ban_score(&self) -> u32 {
        match self {
            OrphanCheckError::StorageError(_) => 0,
            OrphanCheckError::PrevBlockIndexNotFound(_) => 100,
            OrphanCheckError::LocalOrphan => 0,
        }
    }
}

impl BanScore for ConnectTransactionError {
    fn ban_score(&self) -> u32 {
        match self {
            ConnectTransactionError::StorageError(_) => 0,
            ConnectTransactionError::TxNumWrongInBlockOnConnect(_, _) => 100,
            ConnectTransactionError::TxNumWrongInBlockOnDisconnect(_, _) => 0,
            // this is zero because it's used when we add the outputs whose transactions we tested beforehand
            ConnectTransactionError::InvariantBrokenAlreadyUnspent => 0,
            // Even though this is an invariant error, it stems from referencing a block for reward that doesn't exist
            ConnectTransactionError::MissingOutputOrSpent(_) => 100,
            ConnectTransactionError::AttemptToPrintMoney(_, _) => 100,
            ConnectTransactionError::TxFeeTotalCalcFailed(_, _) => 100,
            ConnectTransactionError::SignatureVerificationFailed(_) => 100,
            ConnectTransactionError::BlockHeightArithmeticError => 100,
            ConnectTransactionError::BlockTimestampArithmeticError => 100,
            // Even though this is an invariant error, it stems from a block reward that doesn't exist
            ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoaded(_) => 100,
            ConnectTransactionError::FailedToAddAllFeesOfBlock(_) => 100,
            ConnectTransactionError::RewardAdditionError(_) => 100,
            ConnectTransactionError::TimeLockViolation(_) => 100,
            ConnectTransactionError::MissingBlockUndo(_) => 0,
            ConnectTransactionError::MissingBlockRewardUndo(_) => 0,
            ConnectTransactionError::MissingTxUndo(_) => 0,
            ConnectTransactionError::TxUndoWithDependency(_) => 0,
            ConnectTransactionError::MissingMempoolTxsUndo => 0,
            ConnectTransactionError::UtxoError(err) => err.ban_score(),
            ConnectTransactionError::TokensError(err) => err.ban_score(),
            ConnectTransactionError::TxIndexError(err) => err.ban_score(),
            ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(_, _) => 100,
            ConnectTransactionError::BlockIndexCouldNotBeLoaded(_) => 100,
            ConnectTransactionError::TransactionVerifierError(err) => err.ban_score(),
            ConnectTransactionError::UtxoBlockUndoError(_) => 100,
            ConnectTransactionError::BurnAmountSumError(_) => 100,
            ConnectTransactionError::AttemptToSpendBurnedAmount => 100,
            ConnectTransactionError::PoSAccountingError(err) => err.ban_score(),
            ConnectTransactionError::AccountingBlockUndoError(_) => 100,
            ConnectTransactionError::SpendStakeError(_) => 100,
            ConnectTransactionError::PoolOwnerBalanceNotFound(_) => 0,
            ConnectTransactionError::PoolDataNotFound(_) => 0,
            ConnectTransactionError::MissingTxInputs => 100,
            ConnectTransactionError::UndoFetchFailure => 0,
            ConnectTransactionError::TxVerifierStorage => 0,
            ConnectTransactionError::PoolOwnerRewardCalculationFailed(_, _) => 100,
            ConnectTransactionError::PoolOwnerRewardCannotExceedTotalReward(_, _, _, _) => 100,
            ConnectTransactionError::UnexpectedPoolId(_, _) => 100,
            ConnectTransactionError::DelegationsRewardSumFailed(_, _) => 100,
            ConnectTransactionError::DelegationRewardOverflow(_, _, _, _) => 100,
            ConnectTransactionError::DistributedDelegationsRewardExceedTotal(_, _, _, _) => 100,
            ConnectTransactionError::BlockRewardInputOutputMismatch(_, _) => 100,
            ConnectTransactionError::TotalDelegationBalanceZero(_) => 0,
            ConnectTransactionError::DelegationDataNotFound(_) => 0,
            ConnectTransactionError::DelegationBalanceNotFound(_) => 0,
            ConnectTransactionError::DestinationRetrievalError(err) => err.ban_score(),
            ConnectTransactionError::OutputTimelockError(err) => err.ban_score(),
            ConnectTransactionError::NotEnoughPledgeToCreateStakePool(_, _, _) => 100,
            ConnectTransactionError::NonceIsNotIncremental(..) => 100,
            ConnectTransactionError::AttemptToCreateStakePoolFromAccounts => 100,
            ConnectTransactionError::AttemptToCreateDelegationFromAccounts => 100,
            ConnectTransactionError::MissingTransactionNonce(_) => 100,
            ConnectTransactionError::FailedToIncrementAccountNonce => 0,
            ConnectTransactionError::IOPolicyError(err, _) => err.ban_score(),
            ConnectTransactionError::TokensAccountingError(err) => err.ban_score(),
            ConnectTransactionError::TokensAccountingBlockUndoError(_) => 100,
        }
    }
}

impl BanScore for OutputMaturityError {
    fn ban_score(&self) -> u32 {
        match self {
            OutputMaturityError::InvalidOutputMaturitySettingType(_) => 100,
            OutputMaturityError::InvalidOutputMaturityDistance(_, _, _) => 100,
            OutputMaturityError::InvalidOutputMaturityDistanceValue(_, _) => 100,
        }
    }
}

impl BanScore for SignatureDestinationGetterError {
    fn ban_score(&self) -> u32 {
        match self {
            SignatureDestinationGetterError::SpendingOutputInBlockReward => 100,
            SignatureDestinationGetterError::SpendingFromAccountInBlockReward => 100,
            SignatureDestinationGetterError::SigVerifyOfBurnedOutput => 100,
            SignatureDestinationGetterError::PoolDataNotFound(_) => 100,
            SignatureDestinationGetterError::DelegationDataNotFound(_) => 100,
            SignatureDestinationGetterError::SigVerifyPoSAccountingError(_) => 100,
            SignatureDestinationGetterError::UtxoOutputNotFound(_) => 100,
            SignatureDestinationGetterError::UtxoViewError(_) => 100,
            SignatureDestinationGetterError::TokenDataNotFound(_) => 100,
            SignatureDestinationGetterError::SigVerifyTokensAccountingError(_) => 100,
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
            TransactionVerifierStorageError::TxIndexError(err) => err.ban_score(),
            TransactionVerifierStorageError::UtxoBlockUndoError(_) => 100,
            TransactionVerifierStorageError::TransactionIndexDisabled => 0,
            TransactionVerifierStorageError::PoSAccountingError(err) => err.ban_score(),
            TransactionVerifierStorageError::AccountingBlockUndoError(_) => 100,
            TransactionVerifierStorageError::TokensAccountingError(err) => err.ban_score(),
            TransactionVerifierStorageError::TokensAccountingBlockUndoError(_) => 100,
        }
    }
}

impl BanScore for TxIndexError {
    fn ban_score(&self) -> u32 {
        match self {
            // this is zero because it's used when we add the outputs whose transactions we tested beforehand
            TxIndexError::InvariantBrokenAlreadyUnspent => 0,
            // Even though this is an invariant, we consider it a violation to be overly cautious
            TxIndexError::InvariantErrorTxNumWrongInBlock(_, _) => 0,
            TxIndexError::OutputAlreadyPresentInInputsCache => 100,
            TxIndexError::PreviouslyCachedInputNotFound(_) => 0,
            TxIndexError::MissingOutputOrSpentOutputErasedOnConnect => 100,
            TxIndexError::MissingOutputOrSpentOutputErasedOnDisconnect => 0,
            TxIndexError::InvalidOutputCount => 100,
            TxIndexError::SerializationInvariantError(_) => 100,
            TxIndexError::DoubleSpendAttempt(_) => 100,
            TxIndexError::MissingOutputOrSpent => 100,
            TxIndexError::OutputIndexOutOfRange {
                tx_id: _,
                source_output_index: _,
            } => 100,
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
            CheckBlockError::PrevBlockNotFound(_, _) => 100,
            CheckBlockError::TransactionVerifierError(err) => err.ban_score(),
            CheckBlockError::BlockNotFound(_) => 100,
            CheckBlockError::BlockTimeOrderInvalid(_, _) => 100,
            CheckBlockError::BlockFromTheFuture => 100,
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
            CheckBlockError::StateUpdateFailed(err) => err.ban_score(),
            CheckBlockError::EpochSealError(err) => err.ban_score(),
            CheckBlockError::InvalidParent(_) => 100,
        }
    }
}

impl BanScore for TokensError {
    fn ban_score(&self) -> u32 {
        match self {
            TokensError::StorageError(_) => 0,
            TokensError::IssueError(_, _, _) => 100,
            TokensError::MultipleTokenIssuanceInTransaction(_, _) => 100,
            TokensError::CoinOrTokenOverflow => 100,
            TokensError::InsufficientTokenFees(_, _) => 100,
            TokensError::TransferZeroTokens(_, _) => 100,
            TokensError::TokenIdCantBeCalculated => 100,
            TokensError::TokensInBlockReward => 100,
            TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(_) => 100,
            TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(_) => 100,
        }
    }
}

impl BanScore for CheckBlockTransactionsError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckBlockTransactionsError::DuplicateInputInTransaction(_, _) => 100,
            CheckBlockTransactionsError::DuplicateInputInBlock(_) => 100,
            CheckBlockTransactionsError::EmptyInputsOutputsInTransactionInBlock(_, _) => 100,
            CheckBlockTransactionsError::TokensError(err) => err.ban_score(),
            CheckBlockTransactionsError::InvalidWitnessCount => 100,
            CheckBlockTransactionsError::NoSignatureDataSizeTooLarge(_, _) => 100,
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
            ConsensusPoWError::InvalidPoW(_) => 100,
            ConsensusPoWError::NoInputDataProvided => 100,
            ConsensusPoWError::PoSInputDataProvided => 100,
            ConsensusPoWError::PrevBlockLoadError(_, _) => 0,
            ConsensusPoWError::PrevBlockNotFound(_) => 100,
            ConsensusPoWError::AncestorAtHeightNotFound(_, _, _) => 0,
            ConsensusPoWError::NoPowDataInPreviousBlock => 100,
            ConsensusPoWError::DecodingBitsFailed(_) => 100,
            ConsensusPoWError::PreviousBitsDecodingFailed(_) => 0,
            ConsensusPoWError::InvalidTargetBits(_, _) => 100,
            ConsensusPoWError::InvalidBlockRewardMaturityDistance(_) => 0,
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
            ConsensusPoSError::PropertyQueryError(_) => 0,
            ConsensusPoSError::StakeKernelHashTooHigh => 100,
            ConsensusPoSError::TimestampViolation(_, _) => 100,
            ConsensusPoSError::NoKernel => 100,
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
            E::StorageError(_) => 0,
            E::AccountingError(_) => 100,
            E::InvariantErrorPoolBalanceAlreadyExists => 100,
            E::InvariantErrorPoolDataAlreadyExists => 100,
            E::AttemptedDecommissionNonexistingPoolBalance => 100,
            E::AttemptedDecommissionNonexistingPoolData => 100,
            E::DelegationCreationFailedPoolDoesNotExist => 100,
            E::InvariantErrorDelegationCreationFailedIdAlreadyExists => 100,
            E::DelegateToNonexistingId => 100,
            E::DelegateToNonexistingPool => 100,
            E::AdditionError => 100,
            E::SubError => 100,
            E::DelegationBalanceAdditionError => 100,
            E::DelegationBalanceSubtractionError => 100,
            E::PoolBalanceAdditionError => 100,
            E::PoolBalanceSubtractionError => 100,
            E::DelegationSharesAdditionError => 100,
            E::DelegationSharesSubtractionError => 100,
            E::InvariantErrorPoolCreationReversalFailedBalanceNotFound => 100,
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
            E::InvariantErrorDelegationUndoFailedDataNotFound => 100,
            E::DuplicatesInDeltaAndUndo => 100,
            E::ViewFail => 0,
            E::IncreasePledgeAmountOfNonexistingPool => 100,
            E::PledgeAmountAdditionError => 100,
            E::InvariantErrorIncreasePledgeUndoFailedPoolBalanceNotFound => 100,
            E::InvariantErrorIncreasePledgeUndoFailedPoolDataNotFound => 100,
            E::DelegationDeletionFailedIdDoesNotExist => 100,
            E::DelegationDeletionFailedBalanceNonZero => 100,
            E::DelegationDeletionFailedPoolsShareNonZero => 100,
            E::DelegationDeletionFailedPoolStillExists => 100,
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
            IOPolicyError::AmountOverflow => 100,
            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints => 100,
            IOPolicyError::InputsAndInputsUtxosLengthMismatch(_, _) => 100,
            IOPolicyError::MissingOutputOrSpent(_) => 100,
            IOPolicyError::BlockHeightArithmeticError => 100,
            IOPolicyError::PoSAccountingError(err) => err.ban_score(),
            IOPolicyError::PledgeAmountNotFound(_) => 100,
            IOPolicyError::AttemptToViolateBurnConstraints => 100,
        }
    }
}

impl BanScore for tokens_accounting::Error {
    fn ban_score(&self) -> u32 {
        match self {
            tokens_accounting::Error::StorageError(_) => todo!(),
            tokens_accounting::Error::AccountingError(_) => todo!(),
            tokens_accounting::Error::TokenAlreadyExist(_) => todo!(),
            tokens_accounting::Error::TokenDataNotFound(_) => todo!(),
            tokens_accounting::Error::TokenDataNotFoundOnReversal(_) => todo!(),
            tokens_accounting::Error::CirculatingSupplyNotFound(_) => todo!(),
            tokens_accounting::Error::MintExceedsSupplyLimit(_, _, _) => todo!(),
            tokens_accounting::Error::AmountOverflow => todo!(),
            tokens_accounting::Error::CannotMintFromLockedSupply(_) => todo!(),
            tokens_accounting::Error::CannotRedeemFromLockedSupply(_) => todo!(),
            tokens_accounting::Error::NotEnoughCirculatingSupplyToRedeem(_, _, _) => todo!(),
            tokens_accounting::Error::SupplyIsAlreadyLocked(_) => todo!(),
            tokens_accounting::Error::CannotLockNotLockableSupply(_) => todo!(),
            tokens_accounting::Error::ViewFail => todo!(),
            tokens_accounting::Error::StorageWrite => todo!(),
        }
    }
}

// TODO: tests in which we simulate every possible case and test the score

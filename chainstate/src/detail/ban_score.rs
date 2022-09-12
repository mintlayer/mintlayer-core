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

use super::{
    transaction_verifier::error::ConnectTransactionError, BlockSizeError, CheckBlockError,
    CheckBlockTransactionsError, OrphanCheckError,
};
use crate::BlockError;
use common::chain::tokens::TokensError;
use consensus::{ConsensusPoWError, ConsensusVerificationError};

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
            BlockError::BestBlockLoadError(_) => 0,
            BlockError::InvariantErrorFailedToFindNewChainPath(_, _, _) => 0,
            BlockError::InvariantErrorInvalidTip => 0,
            // Even though this should've been caught by orphans check, its mere presence means a peer sent a block they're not supposed to send
            BlockError::PrevBlockNotFound => 100,
            BlockError::BlockAlreadyExists(_) => 0,
            BlockError::DatabaseCommitError(_, _, _) => 0,
            BlockError::BlockProofCalculationError(_) => 100,
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
            ConnectTransactionError::InvariantErrorTxNumWrongInBlock(_, _) => 0,
            ConnectTransactionError::OutputAlreadyPresentInInputsCache => 100,
            ConnectTransactionError::PreviouslyCachedInputNotFound => 0,
            ConnectTransactionError::PreviouslyCachedInputWasErased => 100,
            ConnectTransactionError::InvariantBrokenAlreadyUnspent => 0,
            // Even though this is an invariant error, it stems from referencing a block for reward that doesn't exist
            ConnectTransactionError::InvariantBrokenSourceBlockIndexNotFound => 100,
            ConnectTransactionError::MissingOutputOrSpent => 100,
            ConnectTransactionError::MissingOutputOrSpentOutputErasedOnConnect => 100,
            ConnectTransactionError::MissingOutputOrSpentOutputErasedOnDisconnect => 0,
            ConnectTransactionError::AttemptToPrintMoney(_, _) => 100,
            ConnectTransactionError::TxFeeTotalCalcFailed(_, _) => 100,
            ConnectTransactionError::OutputAdditionError => 100,
            ConnectTransactionError::SignatureVerificationFailed => 100,
            ConnectTransactionError::InvalidOutputCount => 100,
            ConnectTransactionError::BlockHeightArithmeticError => 100,
            ConnectTransactionError::BlockTimestampArithmeticError => 100,
            ConnectTransactionError::InputAdditionError => 100,
            ConnectTransactionError::DoubleSpendAttempt(_) => 100,
            ConnectTransactionError::OutputIndexOutOfRange {
                tx_id: _,
                source_output_index: _,
            } => 100,
            // Even though this is an invariant error, it stems from a transaction that doesn't exist
            ConnectTransactionError::InvariantErrorTransactionCouldNotBeLoaded(_) => 100,
            // Even though this is an invariant error, it stems from a block reward that doesn't exist
            ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoaded(_) => 100,
            ConnectTransactionError::InvariantErrorBlockIndexCouldNotBeLoaded(_) => 100,
            ConnectTransactionError::InvariantErrorBlockCouldNotBeLoaded(_) => 100,
            ConnectTransactionError::FailedToAddAllFeesOfBlock(_) => 100,
            ConnectTransactionError::RewardAdditionError(_) => 100,
            // Even though this is an invariant, we consider it a violation to be overly cautious
            ConnectTransactionError::SerializationInvariantError(_) => 100,
            ConnectTransactionError::TimeLockViolation => 100,
            ConnectTransactionError::MissingBlockUndo(_) => 0,
            ConnectTransactionError::MissingBlockRewardUndo(_) => 0,
            ConnectTransactionError::MissingTxUndo(_, _) => 0,
            ConnectTransactionError::UtxoError(err) => err.ban_score(),
            ConnectTransactionError::TokensError(err) => err.ban_score(),
        }
    }
}

impl BanScore for CheckBlockError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckBlockError::StorageError(_) => 0,
            CheckBlockError::MerkleRootMismatch => 100,
            CheckBlockError::WitnessMerkleRootMismatch => 100,
            // even though this may be an invariant error, we treat it strictly
            CheckBlockError::PrevBlockNotFound(_, _) => 100,
            CheckBlockError::BlockTimeOrderInvalid => 100,
            CheckBlockError::BlockFromTheFuture => 100,
            CheckBlockError::BlockSizeError(err) => err.ban_score(),
            CheckBlockError::CheckTransactionFailed(err) => err.ban_score(),
            CheckBlockError::ConsensusVerificationFailed(err) => err.ban_score(),
            CheckBlockError::InvalidBlockRewardMaturityDistance(_, _, _) => 100,
            CheckBlockError::InvalidBlockRewardMaturityDistanceValue(_, _) => 100,
            CheckBlockError::InvalidBlockRewardMaturityTimelockType(_) => 100,
            CheckBlockError::InvalidBlockRewardOutputType(_) => 100,
        }
    }
}

impl BanScore for TokensError {
    fn ban_score(&self) -> u32 {
        match self {
            TokensError::IssueErrorInvalidTickerLength(_, _) => 100,
            TokensError::IssueErrorTickerHasNoneAlphaNumericChar(_, _) => 100,
            TokensError::IssueErrorIncorrectAmount(_, _) => 100,
            TokensError::IssueErrorTooManyDecimals(_, _) => 100,
            TokensError::IssueErrorIncorrectMetadataURI(_, _) => 100,
            TokensError::MultipleTokenIssuanceInTransaction(_, _) => 100,
            TokensError::CoinOrTokenOverflow => 100,
            TokensError::InsufficientTokenFees(_, _) => 100,
            TokensError::BurnZeroTokens(_, _) => 100,
            TokensError::NoTxInMainChainByOutpoint => 100,
            TokensError::BlockRewardOutputCantBeUsedInTokenTx => 100,
            TokensError::TransferZeroTokens(_, _) => 100,
            TokensError::TokensNotRegistered(_) => 100,
            TokensError::TokenIdCantBeCalculated => 100,
            TokensError::AttemptToTransferBurnedTokens => 100,
            TokensError::TokensInBlockReward => 100,
            TokensError::InvariantBrokenDuplicateTokenId(_, _) => 100,
            TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(_) => 100,
            TokensError::InvariantBrokenRegisterIssuanceOnNonexistentToken(_) => 100,
            TokensError::InvariantBrokenFlushNonexistentToken(_) => 100,
        }
    }
}

impl BanScore for CheckBlockTransactionsError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckBlockTransactionsError::StorageError(_) => 0,
            CheckBlockTransactionsError::DuplicateInputInTransaction(_, _) => 100,
            CheckBlockTransactionsError::DuplicateInputInBlock(_) => 100,
            CheckBlockTransactionsError::EmptyInputsOutputsInTransactionInBlock(_, _) => 100,
            CheckBlockTransactionsError::DuplicatedTransactionInBlock(_, _) => 100,
            CheckBlockTransactionsError::TokensError(err) => err.ban_score(),
        }
    }
}

impl BanScore for ConsensusVerificationError {
    fn ban_score(&self) -> u32 {
        match self {
            ConsensusVerificationError::StorageError(_) => 0,
            ConsensusVerificationError::PrevBlockLoadError(_, _, _) => 0,
            ConsensusVerificationError::PrevBlockNotFound(_, _) => 100,
            ConsensusVerificationError::ConsensusTypeMismatch(_) => 100,
            ConsensusVerificationError::PoWError(err) => err.ban_score(),
            ConsensusVerificationError::UnsupportedConsensusType => 100,
        }
    }
}

impl BanScore for ConsensusPoWError {
    fn ban_score(&self) -> u32 {
        match self {
            ConsensusPoWError::InvalidPoW(_) => 100,
            ConsensusPoWError::PrevBlockLoadError(_, _, _) => 0,
            ConsensusPoWError::PrevBlockNotFound(_, _) => 100,
            ConsensusPoWError::AncestorAtHeightNotFound(_, _, _) => 0,
            ConsensusPoWError::NoPowDataInPreviousBlock => 100,
            ConsensusPoWError::DecodingBitsFailed(_) => 100,
            ConsensusPoWError::PreviousBitsDecodingFailed(_) => 0,
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

impl BanScore for utxo::Error {
    fn ban_score(&self) -> u32 {
        match self {
            utxo::Error::OverwritingUtxo => 0,
            utxo::Error::FreshUtxoAlreadyExists => 0,
            utxo::Error::UtxoAlreadySpent(_) => 100,
            utxo::Error::NoUtxoFound => 100,
            utxo::Error::NoBlockchainHeightFound => 0,
            utxo::Error::MissingBlockRewardUndo(_) => 0,
            utxo::Error::DBError(_) => 0,
        }
    }
}

// TODO: tests in which we simulate every possible case and test the score

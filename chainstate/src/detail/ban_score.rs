// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::BlockError;

use super::{
    pow::error::ConsensusPoWError, spend_cache::error::StateUpdateError, BlockSizeError,
    CheckBlockError, CheckBlockTransactionsError, ConsensusVerificationError, OrphanCheckError,
};

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
            BlockError::InvariantErrorPrevBlockNotFound => 0,
            // Even though this should've been caught by orphans check, its mere presence means a peer sent a block they're not supposed to send
            BlockError::PrevBlockNotFound => 100,
            BlockError::InvalidBlockSource => 100,
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
            OrphanCheckError::PrevBlockIdNotFound => 100,
            OrphanCheckError::PrevBlockIndexNotFound(_) => 100,
            OrphanCheckError::LocalOrphan => 0,
        }
    }
}

impl BanScore for StateUpdateError {
    fn ban_score(&self) -> u32 {
        match self {
            StateUpdateError::StorageError(_) => 0,
            StateUpdateError::TxNumWrongInBlockOnConnect(_, _) => 100,
            StateUpdateError::TxNumWrongInBlockOnDisconnect(_, _) => 0,
            // this is zero because it's used when we add the outputs whose transactions we tested beforehand
            StateUpdateError::InvariantErrorTxNumWrongInBlock(_, _) => 0,
            StateUpdateError::OutputAlreadyPresentInInputsCache => 100,
            StateUpdateError::ImmatureBlockRewardSpend => 100,
            StateUpdateError::PreviouslyCachedInputNotFound => 0,
            StateUpdateError::PreviouslyCachedInputWasErased => 100,
            StateUpdateError::InvariantBrokenAlreadyUnspent => 0,
            // Even though this is an invariant error, it stems from referencing a block for reward that doesn't exist
            StateUpdateError::InvariantBrokenSourceBlockIndexNotFound => 100,
            StateUpdateError::MissingOutputOrSpent => 100,
            StateUpdateError::MissingOutputOrSpentOutputErasedOnConnect => 100,
            StateUpdateError::MissingOutputOrSpentOutputErasedOnDisconnect => 0,
            StateUpdateError::AttemptToPrintMoney(_, _) => 100,
            StateUpdateError::TxFeeTotalCalcFailed(_, _) => 100,
            StateUpdateError::OutputAdditionError => 100,
            StateUpdateError::SignatureVerificationFailed => 100,
            StateUpdateError::InvalidOutputCount => 100,
            StateUpdateError::BlockHeightArithmeticError => 100,
            StateUpdateError::InputAdditionError => 100,
            StateUpdateError::DoubleSpendAttempt(_) => 100,
            StateUpdateError::OutputIndexOutOfRange {
                tx_id: _,
                source_output_index: _,
            } => 100,
            // Even though this is an invariant error, it stems from a transaction that doesn't exist
            StateUpdateError::InvariantErrorTransactionCouldNotBeLoaded(_) => 100,
            // Even though this is an invariant error, it stems from a block reward that doesn't exist
            StateUpdateError::InvariantErrorHeaderCouldNotBeLoaded(_) => 100,
            StateUpdateError::FailedToAddAllFeesOfBlock(_) => 100,
            StateUpdateError::RewardAdditionError(_) => 100,
            // Even though this is an invariant, we consider it a violation to be overly cautious
            StateUpdateError::SerializationInvariantError(_) => 100,
            StateUpdateError::TimelockViolation => 100,
        }
    }
}

impl BanScore for CheckBlockError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckBlockError::StorageError(_) => 0,
            CheckBlockError::MerkleRootMismatch => 100,
            CheckBlockError::WitnessMerkleRootMismatch => 100,
            CheckBlockError::InvalidBlockNoPrevBlock => 100,
            // even though this may be an invariant error, we treat it strictly
            CheckBlockError::PrevBlockNotFound(_, _) => 100,
            CheckBlockError::BlockTimeOrderInvalid => 100,
            CheckBlockError::BlockFromTheFuture => 100,
            CheckBlockError::BlockSizeError(err) => err.ban_score(),
            CheckBlockError::CheckTransactionFailed(err) => err.ban_score(),
            CheckBlockError::ConsensusVerificationFailed(err) => err.ban_score(),
        }
    }
}

impl BanScore for CheckBlockTransactionsError {
    fn ban_score(&self) -> u32 {
        match self {
            CheckBlockTransactionsError::StorageError(_) => 0,
            CheckBlockTransactionsError::DuplicateInputInTransaction(_, _) => 100,
            CheckBlockTransactionsError::DuplicateInputInBlock(_) => 100,
            CheckBlockTransactionsError::DuplicatedTransactionInBlock(_, _) => 100,
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

// TODO: tests in which we simulate every possible case and test the score

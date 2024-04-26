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

use chainstate::ConnectTransactionError;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub enum OrphanType {
    MissingUtxo,
    AccountNonceGap(u64),
}

impl OrphanType {
    /// Check an error signifies a potential orphan transaction
    pub fn from_error(err: &ConnectTransactionError) -> Option<Self> {
        use ConnectTransactionError as CTE;
        match err {
            // Missing UTXO signifies a possible orphan
            CTE::MissingOutputOrSpent(_) => Some(Self::MissingUtxo),

            // Nonce gap signifies a possible orphan
            CTE::NonceIsNotIncremental(_acct, expected, got) => {
                got.value().checked_sub(expected.value()).map(Self::AccountNonceGap)
            }

            // These do not
            CTE::StorageError(_)
            | CTE::TxNumWrongInBlockOnConnect(_, _)
            | CTE::TxNumWrongInBlockOnDisconnect(_, _)
            | CTE::InvariantBrokenAlreadyUnspent
            | CTE::MissingTxInputs
            | CTE::MissingTxUndo(_)
            | CTE::MissingBlockUndo(_)
            | CTE::MissingBlockRewardUndo(_)
            | CTE::MissingMempoolTxsUndo
            | CTE::AttemptToPrintMoney(_, _)
            | CTE::BlockRewardInputOutputMismatch(_, _)
            | CTE::TxFeeTotalCalcFailed(_, _)
            | CTE::SignatureVerificationFailed(_)
            | CTE::BlockHeightArithmeticError
            | CTE::BlockTimestampArithmeticError
            | CTE::InvariantErrorHeaderCouldNotBeLoaded(_)
            | CTE::InvariantErrorHeaderCouldNotBeLoadedFromHeight(_, _)
            | CTE::BlockIndexCouldNotBeLoaded(_)
            | CTE::FailedToAddAllFeesOfBlock(_)
            | CTE::RewardAdditionError(_)
            | CTE::TimeLockViolation(_)
            | CTE::UtxoError(_)
            | CTE::TokensError(_)
            | CTE::TransactionVerifierError(_)
            | CTE::UtxoBlockUndoError(_)
            | CTE::BaseAccountingBlockUndoError(_)
            | CTE::AccountingBlockUndoError(_)
            | CTE::BurnAmountSumError(_)
            | CTE::AttemptToSpendBurnedAmount
            | CTE::PoSAccountingError(_)
            | CTE::SpendStakeError(_)
            | CTE::StakerBalanceNotFound(_)
            | CTE::PoolDataNotFound(_)
            | CTE::UnexpectedPoolId(_, _)
            | CTE::UndoFetchFailure
            | CTE::TxVerifierStorage
            | CTE::DestinationRetrievalError(_)
            | CTE::OutputTimelockError(_)
            | CTE::NotEnoughPledgeToCreateStakePool(..)
            | CTE::MissingTransactionNonce(_)
            | CTE::AttemptToCreateStakePoolFromAccounts
            | CTE::AttemptToCreateDelegationFromAccounts
            | CTE::FailedToIncrementAccountNonce
            | CTE::TokensAccountingError(_)
            | CTE::TotalFeeRequiredOverflow
            | CTE::InsufficientCoinsFee(_, _)
            | CTE::AttemptToSpendFrozenToken(_)
            | CTE::ConstrainedValueAccumulatorError(_, _)
            | CTE::PoolBalanceNotFound(_)
            | CTE::RewardDistributionError(_)
            | CTE::CheckTransactionError(_)
            | CTE::IOPolicyError(_, _) => None,
        }
    }
}

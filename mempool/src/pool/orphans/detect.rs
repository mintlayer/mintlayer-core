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
    pub fn from_error(err: ConnectTransactionError) -> Result<Self, ConnectTransactionError> {
        use chainstate::tx_verifier::error::InputCheckErrorPayload as ICE;
        use ConnectTransactionError as CTE;

        match &err {
            // Missing UTXO signifies a possible orphan
            CTE::MissingOutputOrSpent(_) => Ok(Self::MissingUtxo),

            // Nonce gap signifies a possible orphan
            CTE::NonceIsNotIncremental(_acct, expected, got) => {
                got.value().checked_sub(expected.value()).map(Self::AccountNonceGap).ok_or(err)
            }

            CTE::InputCheck(e) => match e.error() {
                // Missing UTXO signifies a possible orphan
                ICE::MissingUtxo(_) => Ok(Self::MissingUtxo),
                ICE::UtxoView(_) | ICE::Translation(_) | ICE::Verification(_) => Err(err),
            },

            // These do not
            CTE::StorageError(_)
            | CTE::MissingTxUndo(_)
            | CTE::MissingBlockUndo(_)
            | CTE::MissingBlockRewardUndo(_)
            | CTE::InvariantErrorHeaderCouldNotBeLoadedFromHeight(_, _)
            | CTE::BlockIndexCouldNotBeLoaded(_)
            | CTE::FailedToAddAllFeesOfBlock(_)
            | CTE::RewardAdditionError(_)
            | CTE::UtxoError(_)
            | CTE::TokensError(_)
            | CTE::TransactionVerifierError(_)
            | CTE::UtxoBlockUndoError(_)
            | CTE::AccountingBlockUndoError(_)
            | CTE::BurnAmountSumError(_)
            | CTE::AttemptToSpendBurnedAmount
            | CTE::PoSAccountingError(_)
            | CTE::SpendStakeError(_)
            | CTE::StakerBalanceNotFound(_)
            | CTE::UnexpectedPoolId(_, _)
            | CTE::UndoFetchFailure
            | CTE::TxVerifierStorage
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
            | CTE::RewardDistributionError(_)
            | CTE::CheckTransactionError(_)
            | CTE::OrdersAccountingError(_)
            | CTE::AttemptToCreateOrderFromAccounts
            | CTE::ConcludeInputAmountsDontMatch(_, _)
            | CTE::IOPolicyError(_, _)
            | CTE::ProduceBlockFromStakeChangesStakerDestination(_, _)
            | CTE::IdCreationError(_) => Err(err),
        }
    }
}

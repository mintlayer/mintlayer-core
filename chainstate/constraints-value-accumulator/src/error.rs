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

use common::{
    chain::{AccountType, DelegationId, PoolId, UtxoOutPoint},
    primitives::CoinOrTokenId,
};

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Amount overflow")]
    AmountOverflow,
    #[error("Coin or token overflow {0:?}")]
    CoinOrTokenOverflow(CoinOrTokenId),
    #[error("Attempt to print money {0:?}")]
    AttemptToPrintMoney(CoinOrTokenId),
    #[error("Attempt to print money or violate timelock constraints {0:?}")]
    AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId),
    #[error("Attempt to violate operations fee requirements")]
    AttemptToViolateFeeRequirements,
    #[error("Inputs and inputs utxos length mismatch: {0} vs {1}")]
    InputsAndInputsUtxosLengthMismatch(usize, usize),
    #[error("Output is not found in the cache or database: {0:?}")]
    MissingOutputOrSpent(UtxoOutPoint),
    #[error("PoS accounting error: `{0}`")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("Orders accounting error: `{0}`")]
    OrdersAccountingError(#[from] orders_accounting::Error),
    #[error("Pledge amount not found for pool: `{0}`")]
    PledgeAmountNotFound(PoolId),
    #[error("Spending non-spendable output: `{0:?}`")]
    SpendingNonSpendableOutput(UtxoOutPoint),
    #[error("Balance not found for delegation `{0}`")]
    DelegationBalanceNotFound(DelegationId),
    #[error("Account balance not found for `{0:?}`")]
    AccountBalanceNotFound(AccountType),
    #[error("Negative account balance for `{0:?}`")]
    NegativeAccountBalance(AccountType),
    #[error("Unsupported token version")]
    UnsupportedTokenVersion,
}

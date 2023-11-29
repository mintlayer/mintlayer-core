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
    chain::{DelegationId, PoolId, UtxoOutPoint},
    primitives::CoinOrTokenId,
};

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Attempted to use a invalid input type in block reward")]
    InvalidInputTypeInReward,
    #[error("Attempted to use a invalid output type in block reward")]
    InvalidOutputTypeInReward,
    #[error("Attempted to use a invalid input type in a tx")]
    InvalidInputTypeInTx,
    #[error("Attempted to create multiple stake pools in a single tx")]
    MultiplePoolCreated,
    #[error("Attempted to create multiple delegations in a single tx")]
    MultipleDelegationCreated,
    #[error("Attempted to produce block in a tx")]
    ProduceBlockInTx,
    #[error("Attempted to provide multiple account command inputs in a single tx")]
    MultipleAccountCommands,
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
    #[error("Pledge amount not found for pool: `{0}`")]
    PledgeAmountNotFound(PoolId),
    #[error("Spending non-spendable output: `{0:?}`")]
    SpendingNonSpendableOutput(UtxoOutPoint),
    #[error("Attempt to use account input in block reward")]
    AttemptToUseAccountInputInReward,
    #[error("Failed to query token id for tx")]
    TokenIdQueryFailed,
    #[error("Token id not found for tx")]
    TokenIdNotFound,
    #[error("Token issuance must come from transaction utxo")]
    TokenIssuanceInputMustBeTransactionUtxo,
    #[error("Balance not found for delegation `{0}`")]
    DelegationBalanceNotFound(DelegationId),
}

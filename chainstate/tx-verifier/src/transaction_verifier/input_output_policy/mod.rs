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

use common::{
    chain::{
        block::BlockRewardTransactable, tokens::TokenId, Block, ChainConfig, DelegationId, PoolId,
        Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockHeight, Id, Idable},
};
use pos_accounting::PoSAccountingView;

use thiserror::Error;

use crate::Fee;

use super::{amounts_map::CoinOrTokenId, error::ConnectTransactionError};

mod constraints_accumulator;
mod purposes_check;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum IOPolicyError {
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
    #[error("Error while calculating block height; possibly an overflow")]
    BlockHeightArithmeticError,
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

pub fn check_reward_inputs_outputs_policy(
    reward: &BlockRewardTransactable,
    utxo_view: &impl utxo::UtxosView,
    block_id: Id<Block>,
) -> Result<(), ConnectTransactionError> {
    purposes_check::check_reward_inputs_outputs_purposes(reward, utxo_view, block_id)
}

pub fn check_tx_inputs_outputs_policy<IssuanceTokenIdGetterFunc>(
    tx: &Transaction,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    pos_accounting_view: &impl PoSAccountingView,
    utxo_view: &impl utxo::UtxosView,
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<Fee, ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc:
        Fn(Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    let inputs_utxos = collect_inputs_utxos(&utxo_view, tx.inputs())?;

    purposes_check::check_tx_inputs_outputs_purposes(tx, &inputs_utxos)
        .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))?;

    let inputs_utxos = tx
        .inputs()
        .iter()
        .map(|input| match input {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo_view.utxo(outpoint).map_err(|_| utxo::Error::ViewRead)?.ok_or(
                    ConnectTransactionError::MissingOutputOrSpent(outpoint.clone()),
                )?;
                Ok(Some(utxo.take_output()))
            }
            TxInput::Account(..) | TxInput::AccountCommand(..) => Ok(None),
        })
        .collect::<Result<Vec<_>, ConnectTransactionError>>()?;

    let pledge_getter = |pool_id: PoolId| {
        Ok(pos_accounting_view
            .get_pool_data(pool_id)
            .map_err(|_| pos_accounting::Error::ViewFail)?
            .map(|pool_data| pool_data.pledge_amount()))
    };

    let delegation_balance_getter = |delegation_id: DelegationId| {
        Ok(pos_accounting_view
            .get_delegation_balance(delegation_id)
            .map_err(|_| pos_accounting::Error::ViewFail)?)
    };

    let issuance_token_id_getter =
        |tx_id| issuance_token_id_getter(tx_id).map_err(|_| IOPolicyError::TokenIdQueryFailed);

    let mut constraints_accumulator = constraints_accumulator::ConstrainedValueAccumulator::new();

    constraints_accumulator
        .process_inputs(
            chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            issuance_token_id_getter,
            tx.inputs(),
            &inputs_utxos,
        )
        .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))?;

    constraints_accumulator
        .process_outputs(chain_config, tx.outputs())
        .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))?;

    constraints_accumulator
        .consume(chain_config, block_height)
        .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))
}

// TODO: use FallibleIterator to avoid manually collecting to a Result
fn collect_inputs_utxos(
    utxo_view: &impl utxo::UtxosView,
    inputs: &[TxInput],
) -> Result<Vec<TxOutput>, ConnectTransactionError> {
    inputs
        .iter()
        .filter_map(|input| match input {
            TxInput::Utxo(outpoint) => Some(outpoint),
            TxInput::Account(..) | TxInput::AccountCommand(..) => None,
        })
        .map(|outpoint| {
            utxo_view
                .utxo(outpoint)
                .map_err(|_| utxo::Error::ViewRead)?
                .map(|u| u.output().clone())
                .ok_or(ConnectTransactionError::MissingOutputOrSpent(
                    outpoint.clone(),
                ))
        })
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(test)]
mod tests;

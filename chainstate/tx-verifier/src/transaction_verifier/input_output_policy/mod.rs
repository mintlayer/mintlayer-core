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

use std::collections::BTreeMap;

use accumulated_fee::AccumulatedFee;
use common::{
    chain::{
        block::{BlockRewardTransactable, ConsensusData},
        output_value::OutputValue,
        signature::Signable,
        tokens::{get_tokens_issuance_count, TokenId, TokenIssuanceVersion},
        Block, ChainConfig, DelegationId, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use constraints_accumulator::ConstrainedValueAccumulator;
use pos_accounting::PoSAccountingView;

use thiserror::Error;

use crate::{
    error::{SpendStakeError, TokensError},
    Fee,
};

use super::{error::ConnectTransactionError, CoinOrTokenId, Subsidy};

pub mod accumulated_fee;
pub mod constraints_accumulator;
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

pub fn calculate_tokens_burned_in_outputs(
    tx: &Transaction,
    token_id: &TokenId,
) -> Result<Amount, ConnectTransactionError> {
    tx.outputs()
        .iter()
        .filter_map(|output| match output {
            TxOutput::Burn(output_value) => match output_value {
                OutputValue::Coin(_) | OutputValue::TokenV0(_) => None,
                OutputValue::TokenV1(id, amount) => (id == token_id).then_some(*amount),
            },
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => None,
        })
        .sum::<Option<Amount>>()
        .ok_or(ConnectTransactionError::BurnAmountSumError(tx.get_id()))
}

pub fn check_reward_inputs_outputs_policy(
    chain_config: &ChainConfig,
    utxo_view: &impl utxo::UtxosView,
    block_reward_transactable: BlockRewardTransactable,
    block_id: Id<Block>,
    block_height: BlockHeight,
    consensus_data: &ConsensusData,
    total_fees: Fee,
) -> Result<(), ConnectTransactionError> {
    let block_subsidy_at_height = Subsidy(chain_config.block_subsidy_at_height(&block_height));

    purposes_check::check_reward_inputs_outputs_purposes(
        &block_reward_transactable,
        utxo_view,
        block_id,
    )?;

    match consensus_data {
        ConsensusData::None | ConsensusData::PoW(_) => {
            if let Some(outputs) = block_reward_transactable.outputs() {
                let inputs_accumulator = ConstrainedValueAccumulator::from_block_reward(
                    total_fees,
                    block_subsidy_at_height,
                )
                .ok_or(ConnectTransactionError::RewardAdditionError(block_id))?;

                let outputs_accumulator =
                    ConstrainedValueAccumulator::from_outputs(chain_config, block_height, outputs)
                        .map_err(|e| ConnectTransactionError::IOPolicyError(e, block_id.into()))?;

                inputs_accumulator
                    .satisfy_with(outputs_accumulator)
                    .map_err(|e| ConnectTransactionError::IOPolicyError(e, block_id.into()))?;
            }
        }
        ConsensusData::PoS(_) => {
            match block_reward_transactable.outputs().ok_or(
                ConnectTransactionError::SpendStakeError(SpendStakeError::NoBlockRewardOutputs),
            )? {
                [] => {
                    return Err(ConnectTransactionError::SpendStakeError(
                        SpendStakeError::NoBlockRewardOutputs,
                    ))
                }
                [_] => { /* ok */ }
                _ => {
                    return Err(ConnectTransactionError::SpendStakeError(
                        SpendStakeError::MultipleBlockRewardOutputs,
                    ))
                }
            };
        }
    };
    Ok(())
}

pub fn check_tx_inputs_outputs_policy<IssuanceTokenIdGetterFunc>(
    tx: &Transaction,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    pos_accounting_view: &impl PoSAccountingView,
    utxo_view: &impl utxo::UtxosView,
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<AccumulatedFee, ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc:
        Fn(Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    let inputs_utxos = collect_inputs_utxos(&utxo_view, tx.inputs())?;

    purposes_check::check_tx_inputs_outputs_purposes(tx, &inputs_utxos)
        .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))?;

    // For TokenIssuanceVersion::V0 it is required to provide explicit Burn outputs as token issuance fee.
    let latest_token_version = chain_config
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .token_issuance_version();
    match latest_token_version {
        TokenIssuanceVersion::V0 => {
            check_issuance_fee_burn_v0(chain_config, tx)?;
        }
        TokenIssuanceVersion::V1 => { /* do nothing */ }
    }

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

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        chain_config,
        block_height,
        pledge_getter,
        delegation_balance_getter,
        issuance_token_id_getter,
        tx.inputs(),
        &inputs_utxos,
    )
    .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))?;

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(chain_config, block_height, tx.outputs())
            .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))?;

    let consumed_accumulator = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .map_err(|e| ConnectTransactionError::IOPolicyError(e, tx.get_id().into()))?;

    Ok(consumed_accumulator)
}

fn check_issuance_fee_burn_v0(
    chain_config: &ChainConfig,
    tx: &Transaction,
) -> Result<(), ConnectTransactionError> {
    // Check if the fee is enough for issuance
    let issuance_count = get_tokens_issuance_count(tx.outputs());
    if issuance_count > 0 {
        let total_burned = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::Burn(v) => v.coin_amount(),
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::DelegateStaking(_, _) => None,
            })
            .sum::<Option<Amount>>()
            .ok_or_else(|| ConnectTransactionError::BurnAmountSumError(tx.get_id()))?;

        if total_burned < chain_config.token_min_issuance_fee() {
            return Err(ConnectTransactionError::TokensError(
                TokensError::InsufficientTokenFees(tx.get_id()),
            ));
        }
    }

    Ok(())
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

fn insert_or_increase<K: Ord>(
    collection: &mut BTreeMap<K, Amount>,
    key: K,
    amount: Amount,
) -> Result<(), IOPolicyError> {
    let value = collection.entry(key).or_insert(Amount::ZERO);
    *value = (*value + amount).ok_or(IOPolicyError::AmountOverflow)?;

    Ok(())
}

#[cfg(test)]
mod tests;

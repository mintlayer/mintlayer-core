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
        block::{BlockRewardTransactable, ConsensusData},
        output_value::OutputValue,
        signature::Signable,
        tokens::{get_tokens_issuance_count, TokenId},
        Block, ChainConfig, TokenIssuanceVersion, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight, Fee, Id, Idable, Subsidy},
};
use constraints_value_accumulator::{AccumulatedFee, ConstrainedValueAccumulator};
use orders_accounting::OrdersAccountingView;
use pos_accounting::PoSAccountingView;
use tokens_accounting::TokensAccountingView;

use thiserror::Error;

use crate::error::{SpendStakeError, TokensError};

use super::error::ConnectTransactionError;

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
    #[error("Attempted to create multiple orders in a single tx")]
    MultipleOrdersCreated,
    #[error("Attempted to produce block in a tx")]
    ProduceBlockInTx,
    #[error("Attempted to provide multiple account command inputs in a single tx")]
    MultipleAccountCommands,
    #[error("Attempt to use account input in block reward")]
    AttemptToUseAccountInputInReward,
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
            | TxOutput::DataDeposit(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => None,
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
        chain_config,
        &block_reward_transactable,
        utxo_view,
        block_id,
        block_height,
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
                        .map_err(|e| {
                            ConnectTransactionError::ConstrainedValueAccumulatorError(
                                e,
                                block_id.into(),
                            )
                        })?;

                inputs_accumulator.satisfy_with(outputs_accumulator).map_err(|e| {
                    ConnectTransactionError::ConstrainedValueAccumulatorError(e, block_id.into())
                })?;
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

pub fn check_tx_inputs_outputs_policy(
    tx: &Transaction,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    orders_accounting_view: &impl OrdersAccountingView,
    pos_accounting_view: &impl PoSAccountingView,
    tokens_accounting_view: &impl TokensAccountingView,
    utxo_view: &impl utxo::UtxosView,
) -> Result<AccumulatedFee, ConnectTransactionError> {
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
            TxInput::Account(..)
            | TxInput::AccountCommand(..)
            | TxInput::OrderAccountCommand(..) => Ok(None),
        })
        .collect::<Result<Vec<_>, ConnectTransactionError>>()?;

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        chain_config,
        block_height,
        orders_accounting_view,
        pos_accounting_view,
        tokens_accounting_view,
        tx.inputs(),
        &inputs_utxos,
    )
    .map_err(|e| {
        ConnectTransactionError::ConstrainedValueAccumulatorError(e, tx.get_id().into())
    })?;

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(chain_config, block_height, tx.outputs())
            .map_err(|e| {
                ConnectTransactionError::ConstrainedValueAccumulatorError(e, tx.get_id().into())
            })?;

    let consumed_accumulator =
        inputs_accumulator.satisfy_with(outputs_accumulator).map_err(|e| {
            ConnectTransactionError::ConstrainedValueAccumulatorError(e, tx.get_id().into())
        })?;

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
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_) => None,
            })
            .sum::<Option<Amount>>()
            .ok_or_else(|| ConnectTransactionError::BurnAmountSumError(tx.get_id()))?;

        if total_burned < chain_config.fungible_token_issuance_fee() {
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
            TxInput::Account(..)
            | TxInput::AccountCommand(..)
            | TxInput::OrderAccountCommand(..) => None,
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

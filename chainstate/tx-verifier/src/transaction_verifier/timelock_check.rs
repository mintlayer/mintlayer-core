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

use chainstate_types::{block_index_ancestor_getter, GenBlockIndex};
use common::{
    chain::{
        block::timestamp::BlockTimestamp, signature::Transactable, timelock::OutputTimeLock,
        AccountSpending, ChainConfig, GenBlock, OutPointSourceId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockDistance, BlockHeight, Id},
};
use thiserror::Error;
use utils::ensure;
use utxo::UtxosView;

use super::{
    error::ConnectTransactionError, storage::TransactionVerifierStorageRef,
    TransactionSourceForConnect,
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum OutputMaturityError {
    #[error("Maturity setting type for the output {0:?} is invalid")]
    InvalidOutputMaturitySettingType(UtxoOutPoint),
    #[error("Maturity setting for the output {0:?} is too short: {1} < {2}")]
    InvalidOutputMaturityDistance(UtxoOutPoint, BlockDistance, BlockDistance),
    #[error("Maturity setting value for the output {0:?} is invalid: {1}")]
    InvalidOutputMaturityDistanceValue(UtxoOutPoint, u64),
}

enum OutputTimelockCheckRequired {
    DelegationSpendMaturity,
    DecommissioningMaturity,
}

fn check_timelock(
    source_block_index: &GenBlockIndex,
    timelock: &OutputTimeLock,
    spend_height: &BlockHeight,
    spending_time: &BlockTimestamp,
    outpoint: &UtxoOutPoint,
) -> Result<(), ConnectTransactionError> {
    let source_block_height = source_block_index.block_height();
    let source_block_time = source_block_index.block_timestamp();

    let past_lock = match timelock {
        OutputTimeLock::UntilHeight(h) => spend_height >= h,
        OutputTimeLock::UntilTime(t) => spending_time >= t,
        OutputTimeLock::ForBlockCount(d) => {
            let d: i64 = (*d)
                .try_into()
                .map_err(|_| ConnectTransactionError::BlockHeightArithmeticError)?;
            let d = BlockDistance::from(d);
            *spend_height
                >= (source_block_height + d)
                    .ok_or(ConnectTransactionError::BlockHeightArithmeticError)?
        }
        OutputTimeLock::ForSeconds(dt) => {
            *spending_time
                >= source_block_time
                    .add_int_seconds(*dt)
                    .ok_or(ConnectTransactionError::BlockTimestampArithmeticError)?
        }
    };

    ensure!(
        past_lock,
        ConnectTransactionError::TimeLockViolation(outpoint.clone())
    );

    Ok(())
}

pub fn check_timelocks<S, C, T, U>(
    storage: &S,
    chain_config: &C,
    utxos_view: &U,
    tx: &T,
    tx_source: &TransactionSourceForConnect,
    outpoint_source_id: OutPointSourceId,
    spending_time: &BlockTimestamp,
) -> Result<(), ConnectTransactionError>
where
    S: TransactionVerifierStorageRef,
    C: AsRef<ChainConfig>,
    T: Transactable,
    U: UtxosView,
{
    let inputs = match tx.inputs() {
        Some(inputs) => inputs,
        None => return Ok(()),
    };

    let input_utxos = inputs
        .iter()
        .map(|input| match input {
            TxInput::Utxo(outpoint) => {
                let utxo = utxos_view
                    .utxo(outpoint)
                    .map_err(|_| utxo::Error::ViewRead)?
                    .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
                Ok(Some((outpoint.clone(), utxo)))
            }
            TxInput::Account(_) => Ok(None),
        })
        .collect::<Result<Vec<_>, ConnectTransactionError>>()?;
    debug_assert_eq!(inputs.len(), input_utxos.len());

    let starting_point: GenBlockIndex = match tx_source {
        TransactionSourceForConnect::Chain { new_block_index } => {
            (*new_block_index).clone().into_gen_block_index()
        }
        TransactionSourceForConnect::Mempool { current_best } => (*current_best).clone(),
    };

    // check if utxos can already be spent
    input_utxos.iter().filter_map(|utxo| utxo.as_ref()).try_for_each(| (outpoint, utxo)| -> Result<(), ConnectTransactionError>{
        if let Some(timelock) = utxo.output().timelock() {
            let height = match utxo.source() {
                utxo::UtxoSource::Blockchain(h) => *h,
                utxo::UtxoSource::Mempool => match tx_source {
                    TransactionSourceForConnect::Chain { new_block_index: _ } => {
                        unreachable!("Mempool utxos can never be reached from storage while connecting local transactions")
                    }
                    TransactionSourceForConnect::Mempool { current_best } => {
                        current_best.block_height().next_height()
                    }
                },
            };

            let block_index_getter = |db_tx: &S, _chain_config: &ChainConfig, id: &Id<GenBlock>| {
                db_tx.get_gen_block_index(id)
            };

            let source_block_index = block_index_ancestor_getter(
                block_index_getter,
                storage,
                chain_config.as_ref(),
                (&starting_point).into(),
                height,
            )
            .map_err(|e| {
                ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(e, height)
            })?;

            check_timelock(
                &source_block_index,
                timelock,
                &tx_source.expected_block_height(),
                spending_time,
                outpoint
            )?;
        }
        Ok(())
    })?;

    // check if output timelocks follow the rules
    if let Some(outputs) = tx.outputs() {
        // in case `CreateStakePool`, `ProduceBlockFromStake` utxos are spent or an input from account
        // then produced outputs must be timelocked as per chain config
        let output_check_required = inputs.iter().zip(input_utxos.iter()).find_map(
            |(input, utxo_with_outpoint)| match input {
                TxInput::Utxo(_) => {
                    match utxo_with_outpoint.clone().expect("must be present").1.output() {
                        TxOutput::Transfer(_, _)
                        | TxOutput::LockThenTransfer(_, _, _)
                        | TxOutput::Burn(_)
                        | TxOutput::CreateDelegationId(_, _)
                        | TxOutput::DelegateStaking(_, _) => None,
                        TxOutput::CreateStakePool(_, _) | TxOutput::ProduceBlockFromStake(_, _) => {
                            Some(OutputTimelockCheckRequired::DecommissioningMaturity)
                        }
                    }
                }
                TxInput::Account(account_input) => match account_input.account() {
                    AccountSpending::Delegation(_, _) => {
                        Some(OutputTimelockCheckRequired::DelegationSpendMaturity)
                    }
                },
            },
        );

        if let Some(output_check_required) = output_check_required {
            check_outputs_timelock(
                chain_config.as_ref(),
                outputs,
                tx_source.expected_block_height(),
                output_check_required,
                outpoint_source_id,
            )?;
        }
    }

    Ok(())
}

/// Outputs that decommission a stake pool or spend delegation share must be timelocked
fn check_outputs_timelock(
    chain_config: &ChainConfig,
    outputs: &[TxOutput],
    block_height: BlockHeight,
    output_check_required: OutputTimelockCheckRequired,
    outpoint_source_id: OutPointSourceId,
) -> Result<(), ConnectTransactionError> {
    outputs
        .iter()
        .enumerate()
        .try_for_each(|(index, output)| {
            let outpoint = UtxoOutPoint::new(outpoint_source_id.clone(), index as u32);
            match output {
                TxOutput::Transfer(_, _)
                | TxOutput::Burn(_)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _) => Ok(()),
                TxOutput::LockThenTransfer(_, _, timelock) => match output_check_required {
                    OutputTimelockCheckRequired::DelegationSpendMaturity => {
                        let required =
                            chain_config.as_ref().spend_share_maturity_distance(block_height);
                        check_output_maturity_setting(timelock, required, outpoint)
                    }
                    OutputTimelockCheckRequired::DecommissioningMaturity => {
                        let required =
                            chain_config.as_ref().decommission_pool_maturity_distance(block_height);
                        check_output_maturity_setting(timelock, required, outpoint)
                    }
                },
            }
        })
        .map_err(ConnectTransactionError::OutputTimelockError)
}

pub fn check_output_maturity_setting(
    timelock: &OutputTimeLock,
    required: BlockDistance,
    outpoint: UtxoOutPoint,
) -> Result<(), OutputMaturityError> {
    match timelock {
        OutputTimeLock::ForBlockCount(c) => {
            let cs: i64 = (*c).try_into().map_err(|_| {
                OutputMaturityError::InvalidOutputMaturityDistanceValue(outpoint.clone(), *c)
            })?;
            let given = BlockDistance::new(cs);
            ensure!(
                given >= required,
                OutputMaturityError::InvalidOutputMaturityDistance(outpoint, given, required)
            );
            Ok(())
        }
        OutputTimeLock::UntilHeight(_)
        | OutputTimeLock::UntilTime(_)
        | OutputTimeLock::ForSeconds(_) => Err(
            OutputMaturityError::InvalidOutputMaturitySettingType(outpoint),
        ),
    }
}

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
        ChainConfig, GenBlock, TxOutput,
    },
    primitives::{BlockDistance, BlockHeight, Id},
};
use utils::ensure;
use utxo::UtxosView;

use super::{
    error::ConnectTransactionError, storage::TransactionVerifierStorageRef,
    TransactionSourceForConnect,
};

enum OutputTimelockCheckRequired {
    DelegationSpendMaturity,
    DecommissioningMaturity,
}

fn check_timelock(
    source_block_index: &GenBlockIndex,
    timelock: &OutputTimeLock,
    spend_height: &BlockHeight,
    spending_time: &BlockTimestamp,
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

    ensure!(past_lock, ConnectTransactionError::TimeLockViolation);

    Ok(())
}

pub fn check_timelocks<S, C, T, U>(
    storage: &S,
    chain_config: &C,
    utxos_view: &U,
    tx_source: &TransactionSourceForConnect,
    tx: &T,
    spending_time: &BlockTimestamp,
) -> Result<(), ConnectTransactionError>
where
    S: TransactionVerifierStorageRef,
    C: AsRef<ChainConfig>,
    T: Transactable,
    U: UtxosView,
{
    let inputs = match tx.inputs() {
        Some(ins) => ins,
        None => return Ok(()),
    };

    let input_utxos = inputs
        .iter()
        .map(|input| {
            utxos_view
                .utxo(input.outpoint())
                .map_err(|_| utxo::Error::ViewRead)?
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // in case `CreateStakePool`, `ProduceBlockFromStake` or `DelegateStaking` utxos are spent
    // produced outputs must be timelocked as per chain config
    let output_check_required = input_utxos.iter().find_map(|utxo| match utxo.output() {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateDelegationId(_, _) => None,
        TxOutput::CreateStakePool(_, _) | TxOutput::ProduceBlockFromStake(_, _) => {
            Some(OutputTimelockCheckRequired::DecommissioningMaturity)
        }
        TxOutput::DelegateStaking(_, _) => {
            Some(OutputTimelockCheckRequired::DelegationSpendMaturity)
        }
    });

    let starting_point: GenBlockIndex = match tx_source {
        TransactionSourceForConnect::Chain { new_block_index } => {
            (*new_block_index).clone().into_gen_block_index()
        }
        TransactionSourceForConnect::Mempool { current_best } => (*current_best).clone(),
    };

    // check if utxos can already be spent
    input_utxos.iter().try_for_each(|utxo| -> Result<(), ConnectTransactionError>{
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
            )?;
        }
        Ok(())
    })?;

    // check if output timelocks follow the rules
    if let Some(outputs) = tx.outputs() {
        if let Some(output_check_required) = output_check_required {
            check_outputs_timelock(
                chain_config.as_ref(),
                outputs,
                tx_source.expected_block_height(),
                output_check_required,
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
) -> Result<(), ConnectTransactionError> {
    outputs.iter().try_for_each(|output| match output {
        TxOutput::Transfer(_, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _) => Ok(()),
        TxOutput::LockThenTransfer(_, _, timelock) => match output_check_required {
            OutputTimelockCheckRequired::DelegationSpendMaturity => {
                let required = chain_config.as_ref().spend_share_maturity_distance(block_height);
                check_block_distance(timelock, required)
            }
            OutputTimelockCheckRequired::DecommissioningMaturity => {
                let required =
                    chain_config.as_ref().decommission_pool_maturity_distance(block_height);
                check_block_distance(timelock, required)
            }
        },
    })
}

fn check_block_distance(
    timelock: &OutputTimeLock,
    required: BlockDistance,
) -> Result<(), ConnectTransactionError> {
    match timelock {
        OutputTimeLock::ForBlockCount(c) => {
            let cs: i64 = (*c).try_into().map_err(|_| {
                ConnectTransactionError::InvalidDecommissionMaturityDistanceValue(*c)
            })?;
            let given = BlockDistance::new(cs);
            ensure!(
                given >= required,
                ConnectTransactionError::InvalidDecommissionMaturityDistance(given, required)
            );
            Ok(())
        }
        OutputTimeLock::UntilHeight(_)
        | OutputTimeLock::UntilTime(_)
        | OutputTimeLock::ForSeconds(_) => {
            Err(ConnectTransactionError::InvalidDecommissionMaturityType)
        }
    }
}

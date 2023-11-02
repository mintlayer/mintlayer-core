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
        ChainConfig, GenBlock, TxInput, UtxoOutPoint,
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

pub fn check_timelock(
    source_block_height: &BlockHeight,
    source_block_time: &BlockTimestamp,
    timelock: &OutputTimeLock,
    spend_height: &BlockHeight,
    spending_time: &BlockTimestamp,
    outpoint: &UtxoOutPoint,
) -> Result<(), ConnectTransactionError> {
    let past_lock = match timelock {
        OutputTimeLock::UntilHeight(h) => spend_height >= h,
        OutputTimeLock::UntilTime(t) => spending_time >= t,
        OutputTimeLock::ForBlockCount(d) => {
            let d: i64 = (*d)
                .try_into()
                .map_err(|_| ConnectTransactionError::BlockHeightArithmeticError)?;
            let d = BlockDistance::from(d);
            *spend_height
                >= (*source_block_height + d)
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
                let utxo = utxos_view.utxo(outpoint).map_err(|_| utxo::Error::ViewRead)?.ok_or(
                    ConnectTransactionError::MissingOutputOrSpent(outpoint.clone()),
                )?;
                Ok(Some((outpoint.clone(), utxo)))
            }
            TxInput::Account(..) | TxInput::AccountCommand(..) => Ok(None),
        })
        .collect::<Result<Vec<_>, ConnectTransactionError>>()?;
    debug_assert_eq!(inputs.len(), input_utxos.len());

    let starting_point: GenBlockIndex = match tx_source {
        TransactionSourceForConnect::Chain { new_block_index } => {
            (*new_block_index).clone().into_gen_block_index()
        }
        TransactionSourceForConnect::Mempool {
            current_best,
            effective_height: _,
        } => (*current_best).clone(),
    };

    // check if utxos can already be spent
    for (outpoint, utxo) in input_utxos.iter().filter_map(|utxo| utxo.as_ref()) {
        if let Some(timelock) = utxo.output().timelock() {
            let (height, timestamp) = match utxo.source() {
                utxo::UtxoSource::Blockchain(height) => {
                    let block_index_getter = |db_tx: &S, _cc: &ChainConfig, id: &Id<GenBlock>| {
                        db_tx.get_gen_block_index(id)
                    };

                    let source_block_index = block_index_ancestor_getter(
                        block_index_getter,
                        storage,
                        chain_config.as_ref(),
                        (&starting_point).into(),
                        *height,
                    )
                    .map_err(|e| {
                        ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                            e, *height,
                        )
                    })?;

                    (*height, source_block_index.block_timestamp())
                }
                utxo::UtxoSource::Mempool => match tx_source {
                    TransactionSourceForConnect::Chain { new_block_index: _ } => {
                        unreachable!("Mempool utxos can never be reached from storage while connecting local transactions")
                    }
                    TransactionSourceForConnect::Mempool {
                        current_best: _,
                        effective_height,
                    } => {
                        // We're building upon another transaction in mempool. Treat it is as if it
                        // was included at earliest possible time at earliest possible block.
                        (*effective_height, *spending_time)
                    }
                },
            };

            check_timelock(
                &height,
                &timestamp,
                timelock,
                &tx_source.expected_block_height(),
                spending_time,
                outpoint,
            )?;
        }
    }

    Ok(())
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

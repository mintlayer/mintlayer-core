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

fn get_timelock(output: &TxOutput) -> Option<&OutputTimeLock> {
    match output {
        TxOutput::Transfer(_, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _, _) => None,
        TxOutput::LockThenTransfer(_, _, tl)
        | TxOutput::DecommissionPool(_, _, _, tl)
        | TxOutput::SpendShareFromDelegation(_, _, _, tl) => Some(tl),
    }
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

    let starting_point: GenBlockIndex = match tx_source {
        TransactionSourceForConnect::Chain { new_block_index } => {
            (*new_block_index).clone().into_gen_block_index()
        }
        TransactionSourceForConnect::Mempool { current_best } => (*current_best).clone(),
    };

    for input in inputs {
        let outpoint = input.outpoint();
        let utxo = utxos_view
            .utxo(outpoint)
            .map_err(|_| utxo::Error::ViewRead)?
            .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;

        if let Some(timelock) = get_timelock(utxo.output()) {
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
    }

    Ok(())
}

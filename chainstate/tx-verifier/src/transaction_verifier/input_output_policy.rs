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

use common::chain::{Transaction, TxOutput};

use super::error::ConnectTransactionError;

/// Not all `OutputType`s can be used in a transaction.
/// For example spending `ProduceBlockFromStake` and `StakePool` in a tx is not supported
/// at the moment and considered invalid.
pub fn check_tx_inputs_outputs_purposes(
    tx: &Transaction,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    check_inputs_can_be_used_in_tx(tx, utxo_view)?;
    check_outputs_can_be_used_in_tx(tx)?;
    Ok(())
}

/// Indicates whether an output purpose can be used in a tx as an input
fn is_valid_input_for_tx(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, _) | TxOutput::LockThenTransfer(_, _, _) => true,
        TxOutput::Burn(_) | TxOutput::StakePool(_) | TxOutput::ProduceBlockFromStake(_, _, _) => {
            false
        }
    }
}

/// Indicates whether an output purpose can be used in a tx as an output
fn is_valid_output_for_tx(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::StakePool(_) => true,
        TxOutput::ProduceBlockFromStake(_, _, _) => false,
    }
}

fn check_inputs_can_be_used_in_tx(
    tx: &Transaction,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    let can_be_spent = tx
        .inputs()
        .iter()
        .map(|input| {
            utxo_view
                .utxo(input.outpoint())
                .map_err(utxo::Error::from_view)?
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)
        })
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .all(|utxo| is_valid_input_for_tx(utxo.output()));

    utils::ensure!(
        can_be_spent,
        ConnectTransactionError::AttemptToSpendInvalidOutputType
    );
    Ok(())
}

fn check_outputs_can_be_used_in_tx(tx: &Transaction) -> Result<(), ConnectTransactionError> {
    let are_outputs_valid = tx.outputs().iter().all(is_valid_output_for_tx);

    utils::ensure!(
        are_outputs_valid,
        ConnectTransactionError::AttemptToUseInvalidOutputInTx
    );
    Ok(())
}

// TODO(Gosha): add tests once decommissioning is supported, because the rules will significantly change

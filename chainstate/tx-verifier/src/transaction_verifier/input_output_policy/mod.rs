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

use common::chain::{
    block::BlockRewardTransactable, signature::Signable, Transaction, TxInput, TxOutput,
};
use consensus::ConsensusPoSError;
use utils::ensure;

use itertools::Itertools;

use super::error::{ConnectTransactionError, SpendStakeError};

fn get_inputs_utxos(
    utxo_view: &impl utxo::UtxosView,
    inputs: &[TxInput],
) -> Result<Vec<TxOutput>, ConnectTransactionError> {
    inputs
        .iter()
        .filter_map(|input| match input {
            TxInput::Utxo(outpoint) => Some(outpoint),
            TxInput::Account(_) => None,
        })
        .map(|outpoint| {
            utxo_view
                .utxo(outpoint)
                .map_err(|_| utxo::Error::ViewRead)?
                .map(|u| u.output().clone())
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Not all `TxOutput` combinations can be used in a block reward.
pub fn check_reward_inputs_outputs_purposes(
    reward: &BlockRewardTransactable,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    match reward.inputs() {
        Some(inputs) => {
            let inputs_utxos = get_inputs_utxos(&utxo_view, inputs)?;

            // the rule for single input/output boils down to that the pair should satisfy:
            // `CreateStakePool` | `ProduceBlockFromStake` -> `ProduceBlockFromStake`
            match inputs_utxos.as_slice() {
                // no inputs
                [] => Err(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::ConsensusPoSError(ConsensusPoSError::NoKernel),
                )),
                // single input
                [intput_utxo] => match intput_utxo {
                    TxOutput::Transfer(..)
                    | TxOutput::LockThenTransfer(..)
                    | TxOutput::Burn(..)
                    | TxOutput::CreateDelegationId(..)
                    | TxOutput::DelegateStaking(..) => {
                        Err(ConnectTransactionError::InvalidInputTypeInReward)
                    }
                    TxOutput::CreateStakePool(..) | TxOutput::ProduceBlockFromStake(..) => {
                        let outputs =
                            reward.outputs().ok_or(ConnectTransactionError::SpendStakeError(
                                SpendStakeError::NoBlockRewardOutputs,
                            ))?;
                        match outputs {
                            [] => Err(ConnectTransactionError::SpendStakeError(
                                SpendStakeError::NoBlockRewardOutputs,
                            )),
                            [output] => match output {
                                TxOutput::Transfer(..)
                                | TxOutput::LockThenTransfer(..)
                                | TxOutput::Burn(..)
                                | TxOutput::CreateStakePool(..)
                                | TxOutput::CreateDelegationId(..)
                                | TxOutput::DelegateStaking(..) => {
                                    Err(ConnectTransactionError::InvalidOutputTypeInReward)
                                }
                                TxOutput::ProduceBlockFromStake(..) => Ok(()),
                            },
                            _ => Err(ConnectTransactionError::SpendStakeError(
                                SpendStakeError::MultipleBlockRewardOutputs,
                            )),
                        }
                    }
                },
                // multiple inputs
                _ => Err(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::ConsensusPoSError(ConsensusPoSError::MultipleKernels),
                )),
            }
        }
        None => {
            // if no kernel input is present it's allowed to have multiple `LockThenTransfer` outputs,
            // because this can only happen with PoW block reward.
            let all_lock_then_transfer = reward
                .outputs()
                .ok_or(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::NoBlockRewardOutputs,
                ))?
                .iter()
                .all(|output| match output {
                    TxOutput::LockThenTransfer(..) => true,
                    TxOutput::Transfer(..)
                    | TxOutput::Burn(..)
                    | TxOutput::CreateStakePool(..)
                    | TxOutput::ProduceBlockFromStake(..)
                    | TxOutput::CreateDelegationId(..)
                    | TxOutput::DelegateStaking(..) => false,
                });
            ensure!(
                all_lock_then_transfer,
                ConnectTransactionError::InvalidOutputTypeInReward
            );
            Ok(())
        }
    }
}

/// Not all `TxOutput` combinations can be used in a transaction.
pub fn check_tx_inputs_outputs_purposes(
    tx: &Transaction,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    let inputs_utxos = get_inputs_utxos(&utxo_view, tx.inputs())?;

    match inputs_utxos.as_slice() {
        // no inputs
        [] => todo!("handle accounting inputs"),
        // single input
        [input_utxo] => match tx.outputs() {
            // no outputs
            [] => { /* do nothing, it's ok to burn outputs in this way */ }
            // single output
            [output] => {
                ensure!(
                    is_valid_one_to_one_combination(input_utxo, output),
                    ConnectTransactionError::InvalidOutputTypeInTx
                );
            }
            // multiple outputs
            _ => {
                is_valid_one_to_any_combination_for_tx(input_utxo, tx.outputs())?;
            }
        },
        // multiple inputs
        _ => {
            is_valid_any_to_any_combination_for_tx(inputs_utxos.as_slice(), tx.outputs())?;
        }
    };

    Ok(())
}

#[allow(clippy::unnested_or_patterns)]
fn is_valid_one_to_one_combination(input_utxo: &TxOutput, output: &TxOutput) -> bool {
    match (input_utxo, output) {
        | (TxOutput::Transfer(..), TxOutput::Transfer(..))
        | (TxOutput::Transfer(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::Transfer(..), TxOutput::Burn(..))
        | (TxOutput::Transfer(..), TxOutput::CreateStakePool(..))
        | (TxOutput::Transfer(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::Transfer(..), TxOutput::DelegateStaking(..)) => true,
        | (TxOutput::Transfer(..), TxOutput::ProduceBlockFromStake(..)) => false,
        | (TxOutput::LockThenTransfer(..), TxOutput::Transfer(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::Burn(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::CreateStakePool(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::DelegateStaking(..)) => true,
        | (TxOutput::LockThenTransfer(..), TxOutput::ProduceBlockFromStake(..)) => false,
        | (TxOutput::Burn(..), _) => false,
        | (TxOutput::CreateStakePool(..), TxOutput::Transfer(..))
        | (TxOutput::CreateStakePool(..), TxOutput::Burn(..))
        | (TxOutput::CreateStakePool(..), TxOutput::CreateStakePool(..))
        | (TxOutput::CreateStakePool(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::CreateStakePool(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::CreateStakePool(..), TxOutput::DelegateStaking(..)) => false,
        | (TxOutput::CreateStakePool(..), TxOutput::LockThenTransfer(..)) => true,
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::Transfer(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::Burn(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::CreateStakePool(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::DelegateStaking(..)) => false,
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::LockThenTransfer(..)) => true,
        | (TxOutput::CreateDelegationId(..), _) => false,
        | (TxOutput::DelegateStaking(..), TxOutput::Transfer(..))
        | (TxOutput::DelegateStaking(..), TxOutput::Burn(..))
        | (TxOutput::DelegateStaking(..), TxOutput::CreateStakePool(..))
        | (TxOutput::DelegateStaking(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::DelegateStaking(..), TxOutput::CreateDelegationId(..)) => false,
        | (TxOutput::DelegateStaking(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::DelegateStaking(..), TxOutput::DelegateStaking(..)) => true,
    }
}

fn is_valid_one_to_any_combination_for_tx(
    input_utxo: &TxOutput,
    outputs: &[TxOutput],
) -> Result<(), ConnectTransactionError> {
    if !is_valid_delegation_spending(input_utxo, outputs)
        && !is_valid_pool_decommissioning(input_utxo, outputs)
    {
        let valid_inputs = are_inputs_valid_for_tx(std::slice::from_ref(input_utxo));
        ensure!(valid_inputs, ConnectTransactionError::InvalidInputTypeInTx);
        let valid_outputs = are_outputs_valid_for_tx(outputs);
        ensure!(
            valid_outputs,
            ConnectTransactionError::InvalidOutputTypeInTx
        );
    }
    Ok(())
}

// single CreateStakePool or ProduceBlockFromStake input; any number of LockThenTransfer outputs
fn is_valid_pool_decommissioning(input_utxo: &TxOutput, outputs: &[TxOutput]) -> bool {
    let stake_pool_input = match input_utxo {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..) => false,
        TxOutput::CreateStakePool(..) | TxOutput::ProduceBlockFromStake(..) => true,
    };

    let all_outputs_are_lock_then_transfer = outputs.iter().all(|output| match output {
        TxOutput::Transfer(..)
        | TxOutput::Burn(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..) => false,
        TxOutput::LockThenTransfer(..) => true,
    });

    stake_pool_input && all_outputs_are_lock_then_transfer
}

// single DelegateStaking input; zero or one DelegateStaking output + any number of LockThenTransfer
fn is_valid_delegation_spending(input_utxo: &TxOutput, outputs: &[TxOutput]) -> bool {
    let delegation_input = match input_utxo {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::CreateDelegationId(..) => false,
        TxOutput::DelegateStaking(..) => true,
    };

    let delegation_outputs_count = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::CreateDelegationId(..) => false,
            TxOutput::DelegateStaking(..) => true,
        })
        .count();

    let spend_share_outputs_count = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::CreateDelegationId(..)
            | TxOutput::DelegateStaking(..) => false,
            TxOutput::LockThenTransfer(..) => true,
        })
        .count();

    delegation_input
        && delegation_outputs_count < 2
        && spend_share_outputs_count == outputs.len() - delegation_outputs_count
}

fn is_valid_any_to_any_combination_for_tx(
    inputs_utxos: &[TxOutput],
    outputs: &[TxOutput],
) -> Result<(), ConnectTransactionError> {
    let valid_inputs = are_inputs_valid_for_tx(inputs_utxos);
    ensure!(valid_inputs, ConnectTransactionError::InvalidInputTypeInTx);
    let valid_outputs = are_outputs_valid_for_tx(outputs);
    ensure!(
        valid_outputs,
        ConnectTransactionError::InvalidOutputTypeInTx
    );
    Ok(())
}

fn are_inputs_valid_for_tx(inputs_utxos: &[TxOutput]) -> bool {
    inputs_utxos.iter().all(|input_utxo| match input_utxo {
        TxOutput::Transfer(..) | TxOutput::LockThenTransfer(..) => true,
        TxOutput::Burn(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..) => false,
    })
}

fn are_outputs_valid_for_tx(outputs: &[TxOutput]) -> bool {
    let valid_outputs_types = outputs.iter().all(|output| match output {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..) => true,
        TxOutput::ProduceBlockFromStake(..) => false,
    });

    let is_stake_pool_unique = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::CreateDelegationId(..)
            | TxOutput::DelegateStaking(..) => false,
            TxOutput::CreateStakePool(..) => true,
        })
        .at_most_one()
        .is_ok();

    let is_create_delegation_unique = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::DelegateStaking(..) => false,
            TxOutput::CreateDelegationId(..) => true,
        })
        .at_most_one()
        .is_ok();

    valid_outputs_types && is_stake_pool_unique && is_create_delegation_unique
}

#[cfg(test)]
mod tests;

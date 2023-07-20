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

use crate::transaction_verifier::input_output_policy::IOPolicyError;

use super::super::error::{ConnectTransactionError, SpendStakeError};

// TODO: avoid collecting by using FallibleIterator
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
    // Check inputs
    let inputs_utxos = get_inputs_utxos(&utxo_view, tx.inputs())?;

    let are_inputs_valid = inputs_utxos.iter().all(|input_utxo| match input_utxo {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::ProduceBlockFromStake(..) => true,
        TxOutput::Burn(..) | TxOutput::CreateDelegationId(..) | TxOutput::DelegateStaking(..) => {
            false
        }
    });
    ensure!(are_inputs_valid, IOPolicyError::InvalidInputTypeInTx);

    // Check outputs
    let mut produce_block_outputs_count = 0;
    let mut stake_pool_outputs_count = 0;
    let mut create_delegation_output_count = 0;

    tx.outputs().iter().for_each(|output| match output {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::DelegateStaking(..) => { /* do nothing */ }
        TxOutput::CreateStakePool(..) => {
            stake_pool_outputs_count += 1;
        }
        TxOutput::ProduceBlockFromStake(..) => {
            produce_block_outputs_count += 1;
        }
        TxOutput::CreateDelegationId(..) => {
            create_delegation_output_count += 1;
        }
    });

    ensure!(
        produce_block_outputs_count == 0,
        IOPolicyError::ProduceBlockInTx
    );
    ensure!(
        stake_pool_outputs_count <= 1,
        IOPolicyError::MultiplePoolCreated
    );
    ensure!(
        create_delegation_output_count <= 1,
        IOPolicyError::MultipleDelegationCreated
    );

    Ok(())
}

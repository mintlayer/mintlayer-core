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
        block::BlockRewardTransactable, signature::Signable, Block, Transaction, TxInput, TxOutput,
    },
    primitives::Id,
};
use consensus::ConsensusPoSError;
use utils::ensure;

use crate::transaction_verifier::input_output_policy::IOPolicyError;

use super::super::error::{ConnectTransactionError, SpendStakeError};

/// Not all `TxOutput` combinations can be used in a block reward.
pub fn check_reward_inputs_outputs_purposes(
    reward: &BlockRewardTransactable,
    utxo_view: &impl utxo::UtxosView,
    block_id: Id<Block>,
) -> Result<(), ConnectTransactionError> {
    match reward.inputs() {
        Some(inputs) => {
            // accounts cannot be used in block reward
            inputs.iter().try_for_each(|input| match input {
                TxInput::Utxo(_) => Ok(()),
                TxInput::Account(..)
                | TxInput::AccountCommand(..)
                | TxInput::OrderAccountCommand(..) => Err(ConnectTransactionError::IOPolicyError(
                    IOPolicyError::AttemptToUseAccountInputInReward,
                    block_id.into(),
                )),
            })?;

            let inputs_utxos = super::collect_inputs_utxos(&utxo_view, inputs)?;

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
                    | TxOutput::DelegateStaking(..)
                    | TxOutput::IssueFungibleToken(..)
                    | TxOutput::IssueNft(..)
                    | TxOutput::DataDeposit(..)
                    | TxOutput::Htlc(..)
                    | TxOutput::CreateOrder(..) => Err(ConnectTransactionError::IOPolicyError(
                        IOPolicyError::InvalidInputTypeInReward,
                        block_id.into(),
                    )),
                    TxOutput::CreateStakePool(input_pool_id, _)
                    | TxOutput::ProduceBlockFromStake(_, input_pool_id) => {
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
                                | TxOutput::DelegateStaking(..)
                                | TxOutput::IssueFungibleToken(..)
                                | TxOutput::IssueNft(..)
                                | TxOutput::DataDeposit(..)
                                | TxOutput::Htlc(..)
                                | TxOutput::CreateOrder(..) => {
                                    Err(ConnectTransactionError::IOPolicyError(
                                        IOPolicyError::InvalidOutputTypeInReward,
                                        block_id.into(),
                                    ))
                                }
                                TxOutput::ProduceBlockFromStake(_, output_pool_id) => {
                                    ensure!(
                                        input_pool_id == output_pool_id,
                                        ConnectTransactionError::SpendStakeError(
                                            SpendStakeError::StakePoolIdMismatch(
                                                *input_pool_id,
                                                *output_pool_id
                                            )
                                        )
                                    );
                                    Ok(())
                                }
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
                    | TxOutput::DelegateStaking(..)
                    | TxOutput::IssueFungibleToken(..)
                    | TxOutput::IssueNft(..)
                    | TxOutput::DataDeposit(..)
                    | TxOutput::Htlc(..)
                    | TxOutput::CreateOrder(..) => false,
                });
            ensure!(
                all_lock_then_transfer,
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::InvalidOutputTypeInReward,
                    block_id.into()
                )
            );
            Ok(())
        }
    }
}

/// Not all `TxOutput` combinations can be used in a transaction.
pub fn check_tx_inputs_outputs_purposes(
    tx: &Transaction,
    inputs_utxos: &[TxOutput],
) -> Result<(), IOPolicyError> {
    // Check inputs utxos
    let are_inputs_valid = inputs_utxos.iter().all(|input_utxo| match input_utxo {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::IssueNft(..)
        | TxOutput::Htlc(..) => true,
        TxOutput::Burn(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..)
        | TxOutput::IssueFungibleToken(..)
        | TxOutput::DataDeposit(..)
        | TxOutput::CreateOrder(..) => false,
    });
    ensure!(are_inputs_valid, IOPolicyError::InvalidInputTypeInTx);

    // if provided account command must be unique among other inputs
    let account_commands_count = tx
        .inputs()
        .iter()
        .filter(|input| match input {
            TxInput::Utxo(_) | TxInput::Account(..) => false,
            TxInput::AccountCommand(..) | TxInput::OrderAccountCommand(..) => true,
        })
        .count();

    ensure!(
        account_commands_count <= 1,
        IOPolicyError::MultipleAccountCommands
    );

    // Check outputs
    let mut produce_block_outputs_count = 0;
    let mut stake_pool_outputs_count = 0;
    let mut create_delegation_output_count = 0;
    let mut create_order_output_count = 0;

    tx.outputs().iter().for_each(|output| match output {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::DelegateStaking(..)
        | TxOutput::IssueFungibleToken(..)
        | TxOutput::IssueNft(..)
        | TxOutput::DataDeposit(..)
        | TxOutput::Htlc(..) => { /* do nothing */ }
        TxOutput::CreateStakePool(..) => {
            stake_pool_outputs_count += 1;
        }
        TxOutput::ProduceBlockFromStake(..) => {
            produce_block_outputs_count += 1;
        }
        TxOutput::CreateDelegationId(..) => {
            create_delegation_output_count += 1;
        }
        TxOutput::CreateOrder(..) => {
            create_order_output_count += 1;
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
    ensure!(
        create_order_output_count <= 1,
        IOPolicyError::MultipleOrdersCreated
    );

    Ok(())
}

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

use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    amount_sum,
    chain::{
        block::BlockRewardTransactable, signature::Signable, timelock::OutputTimeLock,
        AccountSpending, ChainConfig, RequiredConsensus, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, BlockDistance, BlockHeight},
};
use pos_accounting::PoSAccountingView;

use thiserror::Error;

use crate::Fee;

use super::error::{ConnectTransactionError, SpendStakeError};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum IOPolicyError {
    #[error("Attempt to use invalid input type in a transaction")]
    InvalidInputTypeInTx,
    #[error("Attempt to use invalid output type in a transaction")]
    InvalidOutputTypeInTx,
    #[error("Attempted to use a invalid input type in block reward")]
    InvalidInputTypeInReward,
    #[error("Attempted to use a invalid output type in block reward")]
    InvalidOutputTypeInReward,
    #[error("Constrained amount overflow")]
    ConstrainedAmountOverflow,
    #[error("Pool identity constrained reached `{0}`: too many pools created")]
    PoolIdentityConstrainedReached(usize),
    #[error("Delegation identity constrained reached `{0}`: too many delegation ids created")]
    DelegationIdentityConstrainedReached(usize),
    #[error("Produce block constrained reached `{0}`")]
    ProduceBlockConstrainedReached(usize),
    #[error("Timelock requirement were not satisfied")]
    TimelockRequirementNotSatisfied,
}

const MAX_POOLS_ALLOWED_TO_CREATE: usize = 1;
const MAX_DELEGATIONS_ALLOWED_TO_CREATE: usize = 1;

struct ConstrainedValueAccumulator {
    //unconstrained_value: OutputValue,
    timelock_requirement: BTreeMap<BlockDistance, Amount>,
    produce_block_requirement: usize,
    pool_identity_constraint: usize,
    delegation_identity_constraint: usize,
}

impl ConstrainedValueAccumulator {
    pub fn new_for_transaction(
        tx: &Transaction,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        pos_accounting_view: &impl PoSAccountingView,
        utxo_view: &impl utxo::UtxosView,
    ) -> Result<Self, ConnectTransactionError> {
        let mut accumulator = Self {
            timelock_requirement: Default::default(),
            produce_block_requirement: 0,
            pool_identity_constraint: MAX_POOLS_ALLOWED_TO_CREATE,
            delegation_identity_constraint: MAX_DELEGATIONS_ALLOWED_TO_CREATE,
        };
        for input in tx.inputs() {
            accumulator.process_tx_input(
                chain_config,
                block_height,
                pos_accounting_view,
                utxo_view,
                input,
            )?;
        }
        Ok(accumulator)
    }

    pub fn new_for_block_reward(
        reward: &BlockRewardTransactable,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        utxo_view: &impl utxo::UtxosView,
        total_fees: Fee,
    ) -> Result<Self, ConnectTransactionError> {
        match reward.inputs() {
            Some(inputs) => {
                let mut accumulator = Self {
                    timelock_requirement: Default::default(),
                    produce_block_requirement: 1,
                    pool_identity_constraint: 0,
                    delegation_identity_constraint: 0,
                };
                for input in inputs {
                    accumulator.process_block_reward_input(utxo_view, input)?;
                }
                Ok(accumulator)
            }
            None => {
                let consensus = chain_config.net_upgrade().consensus_status(block_height);
                let accumulator = match consensus {
                    RequiredConsensus::PoW(_) => {
                        let required_maturity =
                            chain_config.get_proof_of_work_config().reward_maturity_distance();
                        let block_subsidy = chain_config.block_subsidy_at_height(&block_height);
                        let require_amount = amount_sum!(total_fees.0, block_subsidy)
                            .ok_or(IOPolicyError::ConstrainedAmountOverflow)?;
                        Self {
                            timelock_requirement: BTreeMap::from([(
                                required_maturity,
                                require_amount,
                            )]),
                            pool_identity_constraint: 0,
                            delegation_identity_constraint: 0,
                            produce_block_requirement: 0,
                        }
                    }
                    RequiredConsensus::PoS(_) => todo!(),
                    RequiredConsensus::IgnoreConsensus => Self {
                        timelock_requirement: Default::default(),
                        pool_identity_constraint: 0,
                        delegation_identity_constraint: 0,
                        produce_block_requirement: 0,
                    },
                };
                Ok(accumulator)
            }
        }
    }

    pub fn verify_requirement(self) -> Result<(), IOPolicyError> {
        match self.timelock_requirement.iter().find(|(_, amount)| **amount > Amount::ZERO) {
            Some(_) => Err(IOPolicyError::TimelockRequirementNotSatisfied),
            None => Ok(()),
        }
    }

    fn process_block_reward_input(
        &mut self,
        utxo_view: &impl utxo::UtxosView,
        input: &TxInput,
    ) -> Result<(), ConnectTransactionError> {
        match input {
            TxInput::Utxo(outpoint) => {
                let output = utxo_view
                    .utxo(outpoint)
                    .map_err(|_| utxo::Error::ViewRead)?
                    .map(|u| u.output().clone())
                    .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
                match output {
                    TxOutput::Transfer(..)
                    | TxOutput::LockThenTransfer(..)
                    | TxOutput::CreateDelegationId(..)
                    | TxOutput::DelegateStaking(..)
                    | TxOutput::Burn(..) => Err(ConnectTransactionError::IOPolicyError(
                        IOPolicyError::InvalidInputTypeInReward,
                    )),
                    TxOutput::CreateStakePool(..) | TxOutput::ProduceBlockFromStake(..) => Ok(()),
                }
            }
            TxInput::Account(_) => Err(ConnectTransactionError::IOPolicyError(
                IOPolicyError::InvalidInputTypeInReward,
            )),
        }
    }

    fn process_tx_input(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        pos_accounting_view: &impl PoSAccountingView,
        utxo_view: &impl utxo::UtxosView,
        input: &TxInput,
    ) -> Result<(), ConnectTransactionError> {
        match input {
            TxInput::Utxo(outpoint) => {
                let output = utxo_view
                    .utxo(outpoint)
                    .map_err(|_| utxo::Error::ViewRead)?
                    .map(|u| u.output().clone())
                    .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
                match output {
                    TxOutput::Transfer(_, _) | TxOutput::LockThenTransfer(_, _, _) => {
                        // TODO: this arm can be used to calculate transferred amounts
                    }
                    TxOutput::CreateDelegationId(..)
                    | TxOutput::DelegateStaking(..)
                    | TxOutput::Burn(..) => {
                        return Err(ConnectTransactionError::IOPolicyError(
                            IOPolicyError::InvalidInputTypeInTx,
                        ))
                    }
                    TxOutput::CreateStakePool(pool_id, _)
                    | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                        let block_distance =
                            chain_config.as_ref().decommission_pool_maturity_distance(block_height);
                        let pool_balance = pos_accounting_view
                            .get_pool_balance(pool_id)
                            .map_err(|_| pos_accounting::Error::ViewFail)?
                            .ok_or(ConnectTransactionError::PoolOwnerBalanceNotFound(pool_id))?;
                        match self.timelock_requirement.entry(block_distance) {
                            Entry::Vacant(e) => {
                                e.insert(pool_balance);
                            }
                            Entry::Occupied(mut e) => {
                                let new_balance = (*e.get() + pool_balance)
                                    .ok_or(IOPolicyError::ConstrainedAmountOverflow)?;
                                *e.get_mut() = new_balance;
                            }
                        };
                    }
                };
            }
            TxInput::Account(account) => match account.account() {
                AccountSpending::Delegation(_, spend_amount) => {
                    // FIXME: check balance?
                    let block_distance =
                        chain_config.as_ref().spend_share_maturity_distance(block_height);
                    match self.timelock_requirement.entry(block_distance) {
                        Entry::Vacant(e) => {
                            e.insert(*spend_amount);
                        }
                        Entry::Occupied(mut e) => {
                            let new_balance = (*e.get() + *spend_amount)
                                .ok_or(IOPolicyError::ConstrainedAmountOverflow)?;
                            *e.get_mut() = new_balance;
                        }
                    };
                }
            },
        };

        Ok(())
    }

    pub fn process_output(&mut self, output: &TxOutput) -> Result<(), ConnectTransactionError> {
        match output {
            TxOutput::Transfer(_, _) | TxOutput::Burn(_) | TxOutput::DelegateStaking(_, _) => {
                // TODO: this arm can be used to calculate transferred amounts
            }
            TxOutput::LockThenTransfer(value, _, timelock) => match timelock {
                OutputTimeLock::UntilHeight(_)
                | OutputTimeLock::UntilTime(_)
                | OutputTimeLock::ForSeconds(_) => {
                    // TODO: this arm can be used to calculate transferred amounts
                }
                OutputTimeLock::ForBlockCount(block_count) => {
                    if let Some(coins) = value.coin_amount() {
                        let block_count: i64 = (*block_count)
                            .try_into()
                            .map_err(|_| ConnectTransactionError::BlockHeightArithmeticError)?;
                        let distance = BlockDistance::from(block_count);

                        // find max value that can be saturated with the current timelock
                        let range = self.timelock_requirement.range_mut((
                            std::ops::Bound::Unbounded,
                            std::ops::Bound::Included(distance),
                        ));
                        match range.max() {
                            Some((_, amount)) => {
                                let new_value = *amount - coins;
                                *amount = new_value.unwrap_or(Amount::ZERO);
                            }
                            None => {
                                self.timelock_requirement.insert(distance, coins);
                            }
                        };
                    }
                }
            },
            TxOutput::ProduceBlockFromStake(_, _) => {
                self.produce_block_requirement
                    .checked_sub(1)
                    .ok_or(IOPolicyError::ProduceBlockConstrainedReached(0))?;
            }
            TxOutput::CreateStakePool(_, _) => {
                self.pool_identity_constraint.checked_sub(1).ok_or(
                    IOPolicyError::PoolIdentityConstrainedReached(MAX_POOLS_ALLOWED_TO_CREATE),
                )?;
            }
            TxOutput::CreateDelegationId(_, _) => {
                self.delegation_identity_constraint.checked_sub(1).ok_or(
                    IOPolicyError::PoolIdentityConstrainedReached(
                        MAX_DELEGATIONS_ALLOWED_TO_CREATE,
                    ),
                )?;
            }
        };
        Ok(())
    }
}

/// Not all `TxOutput` combinations can be used in a block reward.
pub fn check_reward_inputs_outputs_purposes(
    reward: &BlockRewardTransactable,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    utxo_view: &impl utxo::UtxosView,
    total_fees: Fee,
) -> Result<(), ConnectTransactionError> {
    let mut constrains_accumulator = ConstrainedValueAccumulator::new_for_block_reward(
        reward,
        chain_config,
        block_height,
        utxo_view,
        total_fees,
    )?;

    let outputs = reward.outputs().ok_or(ConnectTransactionError::SpendStakeError(
        SpendStakeError::NoBlockRewardOutputs,
    ))?;
    for output in outputs {
        constrains_accumulator.process_output(output)?;
    }

    constrains_accumulator.verify_requirement()?;

    Ok(())
}

/// Not all `TxOutput` combinations can be used in a transaction.
pub fn check_tx_inputs_outputs_purposes(
    tx: &Transaction,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    pos_accounting_view: &impl PoSAccountingView,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    let mut constrains_accumulator = ConstrainedValueAccumulator::new_for_transaction(
        tx,
        chain_config,
        block_height,
        pos_accounting_view,
        utxo_view,
    )?;

    for output in tx.outputs() {
        constrains_accumulator.process_output(output)?;
    }

    constrains_accumulator.verify_requirement()?;

    Ok(())
}

//#[cfg(test)]
//mod tests;

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

struct ConstrainedValueAccumulator {
    //unconstrained_value: OutputValue,
    timelock_requirement: BTreeMap<BlockDistance, Amount>,
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

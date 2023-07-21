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

use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    chain::{timelock::OutputTimeLock, AccountSpending, ChainConfig, TxInput, TxOutput},
    primitives::{Amount, BlockDistance, BlockHeight},
};
use pos_accounting::PoSAccountingView;

use crate::error::ConnectTransactionError;

use super::IOPolicyError;

/// `ConstrainedValueAccumulator` helps avoiding messy inputs/outputs combinations analysis by
/// providing a set of properties that should be satisfied. For example instead of checking that
/// all outputs are timelocked when the pool is decommissioned `ConstrainedValueAccumulator` gives a way
/// to check that an accumulated output value is locked for sufficient amount of time which allows
/// using other valid inputs and outputs in the same tx.
///
/// TODO: potentially this struct can be extended to collect unconstrained values such as transferred amounts
///       replacing `AmountsMap`
pub struct ConstrainedValueAccumulator {
    timelock_requirement: BTreeMap<BlockDistance, Amount>,
}

impl ConstrainedValueAccumulator {
    pub fn new() -> Self {
        Self {
            timelock_requirement: Default::default(),
        }
    }

    pub fn verify(self) -> Result<(), ConnectTransactionError> {
        match self.timelock_requirement.iter().find(|(_, amount)| **amount > Amount::ZERO) {
            Some((block_distance, _)) => {
                Err(IOPolicyError::TimelockRequirementNotSatisfied(*block_distance).into())
            }
            None => Ok(()),
        }
    }

    pub fn process_input(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        pos_accounting_view: &impl PoSAccountingView,
        utxo_view: &impl utxo::UtxosView,
        input: &TxInput,
    ) -> Result<(), ConnectTransactionError> {
        match input {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo_view
                    .utxo(outpoint)
                    .map_err(|_| utxo::Error::ViewRead)?
                    .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
                match utxo.output() {
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::CreateDelegationId(..)
                    | TxOutput::DelegateStaking(..)
                    | TxOutput::Burn(..) => { /* do nothing */ }
                    TxOutput::CreateStakePool(pool_id, _)
                    | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                        let block_distance =
                            chain_config.as_ref().decommission_pool_maturity_distance(block_height);
                        let pledged_amount = pos_accounting_view
                            .get_pool_data(*pool_id)
                            .map_err(|_| pos_accounting::Error::ViewFail)?
                            .ok_or(ConnectTransactionError::PoolDataNotFound(*pool_id))?
                            .pledge_amount();
                        match self.timelock_requirement.entry(block_distance) {
                            Entry::Vacant(e) => {
                                e.insert(pledged_amount);
                            }
                            Entry::Occupied(mut e) => {
                                let new_balance = (*e.get() + pledged_amount)
                                    .ok_or(IOPolicyError::ConstrainedAmountOverflow)?;
                                *e.get_mut() = new_balance;
                            }
                        };
                    }
                };
            }
            TxInput::Account(account) => match account.account() {
                AccountSpending::Delegation(_, spend_amount) => {
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
            TxOutput::Transfer(_, _)
            | TxOutput::Burn(_)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::CreateDelegationId(_, _) => { /* do nothing */ }
            TxOutput::LockThenTransfer(value, _, timelock) => match timelock {
                OutputTimeLock::UntilHeight(_)
                | OutputTimeLock::UntilTime(_)
                | OutputTimeLock::ForSeconds(_) => { /* do nothing */ }
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
                        if let Some((_, amount)) = range.max() {
                            let new_value = *amount - coins;
                            *amount = new_value.unwrap_or(Amount::ZERO);
                        }
                    }
                }
            },
        };
        Ok(())
    }
}

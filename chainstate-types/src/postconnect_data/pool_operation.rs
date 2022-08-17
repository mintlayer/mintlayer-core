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

use common::primitives::Amount;

use super::error::Error;

pub enum PoolOperation {
    AddStake(Amount),
    RemoveStake(Amount),
    DecommissionPool,
}

impl PoolOperation {
    fn mark_pool_as_decommissioned(&mut self) {
        let replacer_func = |self_| match self_ {
            PoolOperation::AddStake(_amount) => PoolOperation::DecommissionPool,
            PoolOperation::RemoveStake(_amount) => PoolOperation::DecommissionPool,
            PoolOperation::DecommissionPool => unreachable!(),
        };
        replace_with::replace_with_or_abort(self, replacer_func);
    }

    fn decommission_pool(&mut self) -> Result<(), Error> {
        match self {
            PoolOperation::AddStake(_) | PoolOperation::RemoveStake(_) => {
                self.mark_pool_as_decommissioned()
            }
            PoolOperation::DecommissionPool => return Err(Error::PoolAlreadyDecommissioned),
        };
        Ok(())
    }

    fn flip_add_to_remove(&mut self, new_amount: Amount) -> Result<(), Error> {
        let replacer_func = |self_| match self_ {
            PoolOperation::AddStake(_amount) => PoolOperation::RemoveStake(new_amount),
            PoolOperation::RemoveStake(_amount) => unreachable!(),
            PoolOperation::DecommissionPool => unreachable!(),
        };
        replace_with::replace_with_or_abort(self, replacer_func);
        Ok(())
    }

    fn flip_remove_to_add(&mut self, new_amount: Amount) -> Result<(), Error> {
        let replacer_func = |self_| match self_ {
            PoolOperation::AddStake(_amount) => unreachable!(),
            PoolOperation::RemoveStake(_amount) => PoolOperation::AddStake(new_amount),
            PoolOperation::DecommissionPool => unreachable!(),
        };
        replace_with::replace_with_or_abort(self, replacer_func);
        Ok(())
    }

    fn add_stake(&mut self, amount_to_add: Amount) -> Result<(), Error> {
        match self {
            PoolOperation::AddStake(current_amount) => {
                let new_amount = (*current_amount + amount_to_add).ok_or(
                    Error::PoolStakeAdditionArithmeticError(*current_amount, amount_to_add),
                )?;
                *current_amount = new_amount;
            }
            PoolOperation::RemoveStake(current_amount_to_remove) => {
                if amount_to_add > *current_amount_to_remove {
                    let new_amount = (amount_to_add - *current_amount_to_remove).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            *current_amount_to_remove,
                            amount_to_add,
                        ),
                    )?;
                    self.flip_remove_to_add(new_amount)?;
                } else {
                    let new_amount = (*current_amount_to_remove - amount_to_add).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            amount_to_add,
                            *current_amount_to_remove,
                        ),
                    )?;
                    *current_amount_to_remove = new_amount;
                }
            }
            PoolOperation::DecommissionPool => {
                return Err(Error::AttemptedToAddBalanceToDecommissionedPool)
            }
        }
        Ok(())
    }

    fn remove_stake(&mut self, amount_to_remove: Amount) -> Result<(), Error> {
        match self {
            PoolOperation::AddStake(current_amount_to_add) => {
                if amount_to_remove > *current_amount_to_add {
                    let new_amount = (amount_to_remove - *current_amount_to_add).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            *current_amount_to_add,
                            amount_to_remove,
                        ),
                    )?;
                    self.flip_add_to_remove(new_amount)?;
                } else {
                    let new_amount = (*current_amount_to_add - amount_to_remove).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            amount_to_remove,
                            *current_amount_to_add,
                        ),
                    )?;
                    *current_amount_to_add = new_amount;
                }
            }
            PoolOperation::RemoveStake(current_amount_to_remove) => {
                let new_amount = (*current_amount_to_remove + amount_to_remove).ok_or(
                    Error::PoolStakeNegativeAdditionArithmeticError(
                        *current_amount_to_remove,
                        amount_to_remove,
                    ),
                )?;
                *current_amount_to_remove = new_amount;
            }
            PoolOperation::DecommissionPool => {
                return Err(Error::AttemptedToAddBalanceToDecommissionedPool)
            }
        }
        Ok(())
    }

    pub fn incorporate(&mut self, other: PoolOperation) -> Result<(), Error> {
        match other {
            PoolOperation::AddStake(amount) => self.add_stake(amount),
            PoolOperation::RemoveStake(amount) => self.remove_stake(amount),
            PoolOperation::DecommissionPool => self.decommission_pool(),
        }
    }
}

// TODO: test these operations
// TODO: test consecutive operations that lead to adding zero amount

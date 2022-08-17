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
    fn decommission_pool(self) -> Result<Self, Error> {
        match self {
            PoolOperation::AddStake(_) | PoolOperation::RemoveStake(_) => {
                return Ok(Self::DecommissionPool)
            }
            PoolOperation::DecommissionPool => return Err(Error::PoolAlreadyDecommissioned),
        };
    }

    fn add_stake(self, amount_to_add: Amount) -> Result<Self, Error> {
        match self {
            PoolOperation::AddStake(current_amount) => {
                let new_amount = (current_amount + amount_to_add).ok_or(
                    Error::PoolStakeAdditionArithmeticError(current_amount, amount_to_add),
                )?;
                return Ok(Self::AddStake(new_amount));
            }
            PoolOperation::RemoveStake(current_amount_to_remove) => {
                if amount_to_add > current_amount_to_remove {
                    let new_amount = (amount_to_add - current_amount_to_remove).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            current_amount_to_remove,
                            amount_to_add,
                        ),
                    )?;
                    return Ok(Self::AddStake(new_amount));
                } else {
                    let new_amount = (current_amount_to_remove - amount_to_add).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            amount_to_add,
                            current_amount_to_remove,
                        ),
                    )?;
                    return Ok(Self::RemoveStake(new_amount));
                }
            }
            PoolOperation::DecommissionPool => {
                return Err(Error::AttemptedToAddBalanceToDecommissionedPool)
            }
        }
    }

    fn remove_stake(self, amount_to_remove: Amount) -> Result<Self, Error> {
        match self {
            PoolOperation::AddStake(current_amount_to_add) => {
                if amount_to_remove > current_amount_to_add {
                    let new_amount = (amount_to_remove - current_amount_to_add).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            current_amount_to_add,
                            amount_to_remove,
                        ),
                    )?;
                    return Ok(Self::RemoveStake(new_amount));
                } else {
                    let new_amount = (current_amount_to_add - amount_to_remove).ok_or(
                        Error::PoolStakeAdditionArithmeticError(
                            amount_to_remove,
                            current_amount_to_add,
                        ),
                    )?;
                    return Ok(Self::AddStake(new_amount));
                }
            }
            PoolOperation::RemoveStake(current_amount_to_remove) => {
                let new_amount = (current_amount_to_remove + amount_to_remove).ok_or(
                    Error::PoolStakeNegativeAdditionArithmeticError(
                        current_amount_to_remove,
                        amount_to_remove,
                    ),
                )?;
                return Ok(Self::RemoveStake(new_amount));
            }
            PoolOperation::DecommissionPool => {
                return Err(Error::AttemptedToAddBalanceToDecommissionedPool)
            }
        }
    }

    pub fn incorporate(self, other: PoolOperation) -> Result<Self, Error> {
        match other {
            PoolOperation::AddStake(amount) => self.add_stake(amount),
            PoolOperation::RemoveStake(amount) => self.remove_stake(amount),
            PoolOperation::DecommissionPool => self.decommission_pool(),
        }
    }
}

// TODO: test these operations
// TODO: test consecutive operations that lead to adding zero amount

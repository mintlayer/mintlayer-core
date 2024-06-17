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

use std::collections::BTreeMap;

use accounting::combine_amount_delta;
use common::{
    chain::{DelegationId, PoolId},
    primitives::{amount::SignedAmount, Amount},
};
use utils::tap_log::TapLog;

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        pool_data::PoolData,
        view::{FlushablePoSAccountingView, PoSAccountingView},
    },
    DeltaMergeUndo,
};

use super::{data::PoSAccountingDeltaData, PoSAccountingDelta};

fn signed_to_unsigned_pair(
    (k, v): (DelegationId, SignedAmount),
) -> Result<(DelegationId, Amount), Error> {
    let v = v.into_unsigned().ok_or(accounting::Error::ArithmeticErrorToUnsignedFailed)?;
    Ok((k, v))
}

fn sum_maps<K: Ord + Copy>(
    mut m1: BTreeMap<K, Amount>,
    m2: BTreeMap<K, SignedAmount>,
) -> Result<BTreeMap<K, Amount>, Error> {
    for (k, v) in m2 {
        let base_value = match m1.get(&k) {
            Some(pv) => *pv,
            None => Amount::from_atoms(0),
        };
        let base_amount = base_value.into_signed().ok_or(Error::AccountingError(
            accounting::Error::ArithmeticErrorToUnsignedFailed,
        ))?;
        let new_amount = (base_amount + v).ok_or(Error::AccountingError(
            accounting::Error::ArithmeticErrorSumToSignedFailed,
        ))?;
        let new_amount = new_amount.into_unsigned().ok_or(Error::AccountingError(
            accounting::Error::ArithmeticErrorToUnsignedFailed,
        ))?;
        m1.insert(k, new_amount);
    }
    Ok(m1)
}

impl<P: PoSAccountingView> PoSAccountingView for PoSAccountingDelta<P> {
    type Error = Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Self::Error> {
        Ok(self.get_pool_data(pool_id)?.is_some())
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        let parent_balance =
            self.parent.get_pool_balance(pool_id).log_err().map_err(|_| Error::ViewFail)?;
        let local_delta = self.data.pool_balances.data().get(&pool_id).cloned();
        let balance =
            combine_amount_delta(&parent_balance, &local_delta).map_err(Error::AccountingError)?;

        // When combining deltas with amounts it's impossible to distinguish None from Some(Amount::ZERO).
        // Use information from DeltaData to make the decision.
        // Note: if a pool doesn't exist the balance can be non-zero  because of delegations
        if self.pool_exists(pool_id)? || balance.unwrap_or(Amount::ZERO) != Amount::ZERO {
            Ok(balance)
        } else {
            Ok(None)
        }
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        match self.data.pool_data.get_data(&pool_id) {
            accounting::GetDataResult::Present(d) => Ok(Some(d.clone())),
            accounting::GetDataResult::Deleted => Ok(None),
            accounting::GetDataResult::Missing => {
                Ok(self.parent.get_pool_data(pool_id).log_err().map_err(|_| Error::ViewFail)?)
            }
        }
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        let parent_shares = self
            .parent
            .get_pool_delegations_shares(pool_id)
            .log_err()
            .map_err(|_| Error::ViewFail)?;
        let local_shares = self.get_cached_delegations_shares(pool_id);

        let shares = match (parent_shares, local_shares) {
            (None, None) => return Ok(None),
            (None, Some(m)) => m
                .into_iter()
                .map(signed_to_unsigned_pair)
                .collect::<Result<BTreeMap<DelegationId, Amount>, Error>>()?,
            (Some(m), None) => m,
            (Some(m1), Some(m2)) => sum_maps(m1, m2)?,
        };

        // When combining deltas with amounts it's impossible to distinguish None from Some(Amount::ZERO).
        // Use information from DeltaData to make the decision and filter out zero balances for non-existing delegations.
        let result = shares
            .into_iter()
            .filter_map(|(id, share)| match self.get_delegation_data(id) {
                Ok(data) => {
                    if data.is_some() {
                        Some(Ok((id, share)))
                    } else if share != Amount::ZERO {
                        Some(Err(
                            Error::InvariantErrorNonZeroBalanceForNonExistingDelegation,
                        ))
                    } else {
                        None
                    }
                }
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(Some(result))
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        let parent_amount = self
            .parent
            .get_delegation_balance(delegation_id)
            .log_err()
            .map_err(|_| Error::ViewFail)?;
        let local_amount = self.data.delegation_balances.data().get(&delegation_id).copied();
        let balance =
            combine_amount_delta(&parent_amount, &local_amount).map_err(Error::AccountingError)?;

        // When combining deltas with amounts it's impossible to distinguish None from Some(Amount::ZERO).
        // Use information from DeltaData to make the decision.
        if self.get_delegation_data(delegation_id)?.is_some() {
            Ok(balance)
        } else {
            utils::ensure!(
                balance.unwrap_or(Amount::ZERO) == Amount::ZERO,
                Error::InvariantErrorNonZeroBalanceForNonExistingDelegation
            );
            Ok(None)
        }
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        match self.data.delegation_data.get_data(&delegation_id) {
            accounting::GetDataResult::Present(d) => Ok(Some(d.clone())),
            accounting::GetDataResult::Deleted => Ok(None),
            accounting::GetDataResult::Missing => Ok(self
                .parent
                .get_delegation_data(delegation_id)
                .log_err()
                .map_err(|_| Error::ViewFail)?),
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        let parent_amount = self
            .parent
            .get_pool_delegation_share(pool_id, delegation_id)
            .log_err()
            .map_err(|_| Error::ViewFail)?;
        let local_amount =
            self.data.pool_delegation_shares.data().get(&(pool_id, delegation_id)).copied();
        let balance =
            combine_amount_delta(&parent_amount, &local_amount).map_err(Error::AccountingError)?;

        // When combining deltas with amounts it's impossible to distinguish None from Some(Amount::ZERO).
        // Use information from DeltaData to make the decision.
        if self.get_delegation_data(delegation_id)?.is_some() {
            Ok(balance)
        } else {
            utils::ensure!(
                balance.unwrap_or(Amount::ZERO) == Amount::ZERO,
                Error::InvariantErrorNonZeroBalanceForNonExistingDelegation
            );
            Ok(None)
        }
    }
}

impl<P: PoSAccountingView> FlushablePoSAccountingView for PoSAccountingDelta<P> {
    fn batch_write_delta(&mut self, data: PoSAccountingDeltaData) -> Result<DeltaMergeUndo, Error> {
        self.merge_with_delta(data)
    }
}

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
use common::primitives::{signed_amount::SignedAmount, Amount};

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        pool_data::PoolData,
        view::{FlushablePoSAccountingView, PoSAccountingView},
    },
    DelegationId, PoolId,
};

use super::{data::PoSAccountingDeltaData, PoSAccountingDelta, PoSAccountingViewCow};

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

impl<'a, P: PoSAccountingView> PoSAccountingView for PoSAccountingViewCow<'a, P> {
    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Error> {
        self.as_bounded_ref().pool_exists(pool_id)
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error> {
        self.as_bounded_ref().get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error> {
        self.as_bounded_ref().get_pool_data(pool_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error> {
        self.as_bounded_ref().get_pool_delegations_shares(pool_id)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error> {
        self.as_bounded_ref().get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error> {
        self.as_bounded_ref().get_delegation_data(delegation_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        self.as_bounded_ref().get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<'a, P: PoSAccountingView> PoSAccountingView for PoSAccountingDelta<'a, P> {
    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Error> {
        Ok(self
            .get_pool_data(pool_id)?
            .ok_or_else(|| self.parent.get_pool_data(pool_id))
            .is_ok())
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error> {
        let parent_balance = self.parent.get_pool_balance(pool_id)?;
        let local_delta = self.data.pool_balances.data().get(&pool_id).cloned();
        combine_amount_delta(&parent_balance, &local_delta).map_err(Error::AccountingError)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error> {
        match self.data.pool_data.get_data(&pool_id) {
            accounting::GetDataResult::Present(d) => Ok(Some(d.clone())),
            accounting::GetDataResult::Deleted => Ok(None),
            accounting::GetDataResult::Missing => self.parent.get_pool_data(pool_id),
        }
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error> {
        let parent_shares = self.parent.get_pool_delegations_shares(pool_id)?;
        let local_shares = self.get_cached_delegations_shares(pool_id);

        match (parent_shares, local_shares) {
            (None, None) => Ok(None),
            (None, Some(m)) => Ok(Some(
                m.into_iter()
                    .map(signed_to_unsigned_pair)
                    .collect::<Result<BTreeMap<DelegationId, Amount>, Error>>()?,
            )),
            (Some(m), None) => Ok(Some(m)),
            (Some(m1), Some(m2)) => Ok(Some(sum_maps(m1, m2)?)),
        }
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_delegation_balance(delegation_id)?;
        let local_amount = self.data.delegation_balances.data().get(&delegation_id).copied();
        combine_amount_delta(&parent_amount, &local_amount).map_err(Error::AccountingError)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error> {
        match self.data.delegation_data.get_data(&delegation_id) {
            accounting::GetDataResult::Present(d) => Ok(Some(d.clone())),
            accounting::GetDataResult::Deleted => Ok(None),
            accounting::GetDataResult::Missing => self.parent.get_delegation_data(delegation_id),
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_pool_delegation_share(pool_id, delegation_id)?;
        let local_amount =
            self.data.pool_delegation_shares.data().get(&(pool_id, delegation_id)).copied();
        combine_amount_delta(&parent_amount, &local_amount).map_err(Error::AccountingError)
    }
}

impl<'a, P: PoSAccountingView> FlushablePoSAccountingView for PoSAccountingDelta<'a, P> {
    fn batch_write_delta(&mut self, data: PoSAccountingDeltaData) -> Result<(), Error> {
        self.merge_with_delta(data).map(|_| ())
    }
}

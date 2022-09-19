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

use common::primitives::{Amount, H256};

use crate::{error::Error, DelegationId, PoolId};

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

pub struct PoSAccountingOperationsCache<'a> {
    parent: &'a dyn PoSAccountingView,
    pool_data: BTreeMap<PoolId, PoolData>,
    pool_balances: BTreeMap<PoolId, Amount>,
    pool_delegation_shares: BTreeMap<(PoolId, DelegationId), Amount>,
    delegation_balances: BTreeMap<DelegationId, Amount>,
    delegation_data: BTreeMap<DelegationId, DelegationData>,
}

impl<'a> PoSAccountingOperationsCache<'a> {
    pub fn new(parent: &'a dyn PoSAccountingView) -> Self {
        Self {
            parent,
            pool_data: Default::default(),
            pool_balances: Default::default(),
            pool_delegation_shares: Default::default(),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
        }
    }

    fn get_cached_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Option<BTreeMap<DelegationId, Amount>> {
        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = self.pool_delegation_shares.range(range_start..=range_end);
        let result = range.map(|((_, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

impl<'a> PoSAccountingView for PoSAccountingOperationsCache<'a> {
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error> {
        match self.pool_balances.get(&pool_id) {
            Some(v) => Ok(Some(*v)),
            None => self.parent.get_pool_balance(pool_id),
        }
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error> {
        match self.pool_data.get(&pool_id) {
            Some(v) => Ok(Some(v.clone())),
            None => self.parent.get_pool_data(pool_id),
        }
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error> {
        let parent_shares = self.parent.get_pool_delegations_shares(pool_id)?.unwrap_or_default();
        let local_shares = self.get_cached_delegations_shares(pool_id).unwrap_or_default();
        if parent_shares.is_empty() && local_shares.is_empty() {
            Ok(None)
        } else {
            // TODO: test that local shares overwrite parent shares
            Ok(Some(
                parent_shares.into_iter().chain(local_shares).collect(),
            ))
        }
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error> {
        match self.delegation_balances.get(&delegation_id) {
            Some(v) => Ok(Some(*v)),
            None => self.parent.get_delegation_balance(delegation_id),
        }
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error> {
        match self.delegation_data.get(&delegation_id) {
            Some(v) => Ok(Some(v.clone())),
            None => self.parent.get_delegation_data(delegation_id),
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        match self.pool_delegation_shares.get(&(pool_id, delegation_id)) {
            Some(v) => Ok(Some(*v)),
            None => self.parent.get_pool_delegation_share(pool_id, delegation_id),
        }
    }
}

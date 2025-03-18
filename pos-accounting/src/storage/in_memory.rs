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

use common::{
    chain::{DelegationId, PoolData, PoolId},
    primitives::{Amount, H256},
};

use crate::{pool::delegation::DelegationData, PoSAccountingData};

use super::{PoSAccountingStorageRead, PoSAccountingStorageWrite};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryPoSAccounting {
    pool_data: BTreeMap<PoolId, PoolData>,
    pool_balances: BTreeMap<PoolId, Amount>,
    pool_delegation_shares: BTreeMap<(PoolId, DelegationId), Amount>,
    delegation_balances: BTreeMap<DelegationId, Amount>,
    delegation_data: BTreeMap<DelegationId, DelegationData>,
}

impl InMemoryPoSAccounting {
    pub fn new() -> Self {
        Self {
            pool_data: Default::default(),
            pool_balances: Default::default(),
            pool_delegation_shares: Default::default(),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
        }
    }

    pub fn from_data(data: PoSAccountingData) -> Self {
        Self {
            pool_data: data.pool_data,
            pool_balances: data.pool_balances,
            pool_delegation_shares: data.pool_delegation_shares,
            delegation_balances: data.delegation_balances,
            delegation_data: data.delegation_data,
        }
    }

    pub fn from_values(
        pool_data: BTreeMap<PoolId, PoolData>,
        pool_balances: BTreeMap<PoolId, Amount>,
        pool_delegation_shares: BTreeMap<(PoolId, DelegationId), Amount>,
        delegation_balances: BTreeMap<DelegationId, Amount>,
        delegation_data: BTreeMap<DelegationId, DelegationData>,
    ) -> Self {
        Self {
            pool_data,
            pool_balances,
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        }
    }

    pub fn all_pool_data(&self) -> &BTreeMap<PoolId, PoolData> {
        &self.pool_data
    }

    pub fn all_delegation_data(&self) -> &BTreeMap<DelegationId, DelegationData> {
        &self.delegation_data
    }

    pub fn all_delegation_balances(&self) -> &BTreeMap<DelegationId, Amount> {
        &self.delegation_balances
    }

    #[cfg(test)]
    pub(crate) fn check_consistency(&self) {
        // pool_balance and pool_data must contain the same keys

        assert_eq!(self.pool_balances.len(), self.pool_data.len());
        self.pool_balances.keys().for_each(|key| {
            assert!(
                self.pool_data.contains_key(key),
                "Pool data doesn't exist for {}",
                key
            )
        });

        // delegation_balance and delegation_data must contain the same keys
        //
        // Note: delegation_balances and delegation_data can have different length
        // because zero balances are removed.
        self.delegation_balances.keys().for_each(|key| {
            assert!(
                self.delegation_data.contains_key(key),
                "Delegation data doesn't exist for {}",
                key
            )
        });

        // pool balance = pledge amount + delegations balances
        self.pool_balances.iter().for_each(|(pool_id, pool_balance)| {
            let pool_data = self.pool_data.get(pool_id).expect("pool_data is missing");
            let total_delegations_balance = self
                .pool_delegation_shares
                .iter()
                .filter_map(|((key, _), v)| if key == pool_id { Some(*v) } else { None })
                .sum::<Option<Amount>>()
                .expect("Delegation balance must not overflow");
            assert_eq!(
                Some(*pool_balance),
                pool_data.staker_balance().expect("no overflow") + total_delegations_balance,
                "Pledge amount and delegations don't add up to pool balance {}",
                pool_id
            );
        });

        // delegation balances and delegation shares must contain the same amounts
        assert_eq!(
            self.delegation_balances.len(),
            self.pool_delegation_shares.len()
        );
        self.pool_delegation_shares.iter().for_each(|((_, key), balance)| {
            assert_eq!(
                self.delegation_balances.get(key),
                Some(balance),
                "Delegation shares and balance mismatch for: {}",
                key
            )
        });
    }
}

impl PoSAccountingStorageRead for InMemoryPoSAccounting {
    type Error = crate::Error;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        Ok(self.pool_balances.get(&pool_id).copied())
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = self.pool_delegation_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        Ok(self.delegation_data.get(&delegation_id).cloned())
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        Ok(self.delegation_balances.get(&delegation_id).copied())
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        Ok(self.pool_delegation_shares.get(&(pool_id, delegation_id)).copied())
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        Ok(self.pool_data.get(&pool_id).cloned())
    }
}

impl PoSAccountingStorageWrite for InMemoryPoSAccounting {
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> Result<(), Self::Error> {
        self.pool_balances.insert(pool_id, amount);
        Ok(())
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), Self::Error> {
        self.pool_balances.remove(&pool_id);
        Ok(())
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), Self::Error> {
        self.delegation_balances.insert(delegation_target, amount);
        Ok(())
    }

    fn del_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
    ) -> Result<(), Self::Error> {
        self.delegation_balances.remove(&delegation_target);
        Ok(())
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), Self::Error> {
        self.pool_delegation_shares.insert((pool_id, delegation_id), amount);
        Ok(())
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), Self::Error> {
        self.pool_delegation_shares.remove(&(pool_id, delegation_id));
        Ok(())
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> Result<(), Self::Error> {
        self.delegation_data.insert(delegation_id, delegation_data.clone());
        Ok(())
    }

    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> Result<(), Self::Error> {
        self.delegation_data.remove(&delegation_id);
        Ok(())
    }

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> Result<(), Self::Error> {
        self.pool_data.insert(pool_id, pool_data.clone());
        Ok(())
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), Self::Error> {
        self.pool_data.remove(&pool_id);
        Ok(())
    }
}

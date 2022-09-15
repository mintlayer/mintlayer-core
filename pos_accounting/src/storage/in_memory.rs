use std::collections::BTreeMap;

use chainstate_types::storage_result::Error;
use common::primitives::{Amount, H256};

use crate::{
    pool::{delegation::DelegationData, pool_data::PoolData},
    DelegationId, PoolId,
};

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
}

impl PoSAccountingStorageRead for InMemoryPoSAccounting {
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error> {
        Ok(self.pool_balances.get(&pool_id).copied())
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error> {
        let range_start = (pool_id, DelegationId(H256::zero()));
        let range_end = (pool_id, DelegationId(H256::repeat_byte(0xFF)));
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
    ) -> Result<Option<DelegationData>, Error> {
        Ok(self.delegation_data.get(&delegation_id).cloned())
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error> {
        Ok(self.delegation_balances.get(&delegation_id).copied())
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        Ok(self.pool_delegation_shares.get(&(pool_id, delegation_id)).copied())
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error> {
        Ok(self.pool_data.get(&pool_id).cloned())
    }
}

impl PoSAccountingStorageWrite for InMemoryPoSAccounting {
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> Result<(), Error> {
        self.pool_balances.insert(pool_id, amount);
        Ok(())
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), Error> {
        self.pool_balances.remove(&pool_id);
        Ok(())
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), Error> {
        self.delegation_balances.insert(delegation_target, amount);
        Ok(())
    }

    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> Result<(), Error> {
        self.delegation_balances.remove(&delegation_target);
        Ok(())
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), Error> {
        self.pool_delegation_shares.insert((pool_id, delegation_id), amount);
        Ok(())
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), Error> {
        self.pool_delegation_shares.remove(&(pool_id, delegation_id));
        Ok(())
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> Result<(), Error> {
        self.delegation_data.insert(delegation_id, delegation_data.clone());
        Ok(())
    }

    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> Result<(), Error> {
        self.delegation_data.remove(&delegation_id);
        Ok(())
    }

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> Result<(), Error> {
        self.pool_data.insert(pool_id, pool_data.clone());
        Ok(())
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), Error> {
        self.pool_data.remove(&pool_id);
        Ok(())
    }
}

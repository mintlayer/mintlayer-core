use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::pool::{delegation::DelegationData, pool_data::PoolData};

use chainstate_types::storage_result::Error;

use super::{PoSAccountingStorageRead, PoSAccountingStorageWrite};

#[derive(Clone, Eq, PartialEq)]
pub struct InMemoryPoSAccounting {
    pool_data: BTreeMap<H256, PoolData>,
    pool_balances: BTreeMap<H256, Amount>,
    pool_delegation_shares: BTreeMap<(H256, H256), Amount>,
    delegation_balances: BTreeMap<H256, Amount>,
    delegation_data: BTreeMap<H256, DelegationData>,
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
}

impl PoSAccountingStorageRead for InMemoryPoSAccounting {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        Ok(self.pool_balances.get(&pool_id).copied())
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        let range_start = (pool_id, H256::zero());
        let range_end = (pool_id, H256::repeat_byte(0xFF));
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
        delegation_address: H256,
    ) -> Result<Option<DelegationData>, Error> {
        Ok(self.delegation_data.get(&delegation_address).cloned())
    }

    fn get_delegation_balance(&self, delegation_address: H256) -> Result<Option<Amount>, Error> {
        Ok(self.delegation_balances.get(&delegation_address).copied())
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_address: H256,
    ) -> Result<Option<Amount>, Error> {
        Ok(self.pool_delegation_shares.get(&(pool_id, delegation_address)).copied())
    }

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error> {
        Ok(self.pool_data.get(&pool_id).cloned())
    }
}

impl PoSAccountingStorageWrite for InMemoryPoSAccounting {
    fn set_pool_balance(&mut self, pool_id: H256, amount: Amount) -> Result<(), Error> {
        self.pool_balances.insert(pool_id, amount);
        Ok(())
    }

    fn del_pool_balance(&mut self, pool_id: H256) -> Result<(), Error> {
        self.pool_balances.remove(&pool_id);
        Ok(())
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount: Amount,
    ) -> Result<(), Error> {
        self.delegation_balances.insert(delegation_target, amount);
        Ok(())
    }

    fn del_delegation_balance(&mut self, delegation_target: H256) -> Result<(), Error> {
        self.delegation_balances.remove(&delegation_target);
        Ok(())
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: H256,
        delegation_address: H256,
        amount: Amount,
    ) -> Result<(), Error> {
        self.pool_delegation_shares.insert((pool_id, delegation_address), amount);
        Ok(())
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: H256,
        delegation_address: H256,
    ) -> Result<(), Error> {
        self.pool_delegation_shares.remove(&(pool_id, delegation_address));
        Ok(())
    }

    fn set_delegation_data(
        &mut self,
        delegation_address: H256,
        delegation_data: &DelegationData,
    ) -> Result<(), Error> {
        self.delegation_data.insert(delegation_address, delegation_data.clone());
        Ok(())
    }

    fn del_delegation_data(&mut self, delegation_address: H256) -> Result<(), Error> {
        self.delegation_data.remove(&delegation_address);
        Ok(())
    }

    fn set_pool_data(&mut self, pool_id: H256, pool_data: &PoolData) -> Result<(), Error> {
        self.pool_data.insert(pool_id, pool_data.clone());
        Ok(())
    }

    fn del_pool_data(&mut self, pool_id: H256) -> Result<(), Error> {
        self.pool_data.remove(&pool_id);
        Ok(())
    }
}

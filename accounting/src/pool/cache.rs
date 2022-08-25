use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::error::Error;

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

pub struct PoSAccountingOperationsCache<'a> {
    parent: &'a dyn PoSAccountingView,
    pool_data: BTreeMap<H256, PoolData>,
    pool_balances: BTreeMap<H256, Amount>,
    pool_delegation_shares: BTreeMap<(H256, H256), Amount>,
    delegation_balances: BTreeMap<H256, Amount>,
    delegation_data: BTreeMap<H256, DelegationData>,
}

impl<'a> PoSAccountingOperationsCache<'a> {
    fn get_cached_delegations_shares(&self, pool_id: H256) -> Option<BTreeMap<H256, Amount>> {
        let range_start = (pool_id, H256::zero());
        let range_end = (pool_id, H256::repeat_byte(0xFF));
        let range = self.pool_delegation_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

impl<'a> PoSAccountingView for PoSAccountingOperationsCache<'a> {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        match self.pool_balances.get(&pool_id) {
            Some(v) => Ok(Some(*v)),
            None => self.parent.get_pool_balance(pool_id),
        }
    }

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error> {
        match self.pool_data.get(&pool_id) {
            Some(v) => Ok(Some(v.clone())),
            None => self.parent.get_pool_data(pool_id),
        }
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        match self.get_cached_delegations_shares(pool_id) {
            Some(v) => Ok(Some(v)),
            None => self.parent.get_pool_delegations_shares(pool_id),
        }
    }

    fn get_delegation_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        match self.delegation_balances.get(&delegation_id) {
            Some(v) => Ok(Some(*v)),
            None => self.parent.get_delegation_balance(delegation_id),
        }
    }

    fn get_delegation_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error> {
        match self.delegation_data.get(&delegation_id) {
            Some(v) => Ok(Some(v.clone())),
            None => self.parent.get_delegation_data(delegation_id),
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        match self.pool_delegation_shares.get(&(pool_id, delegation_id)) {
            Some(v) => Ok(Some(*v)),
            None => self.parent.get_pool_delegation_share(pool_id, delegation_id),
        }
    }
}

use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::pool::delegation::DelegationData;

use chainstate_types::storage_result::Error;

use super::PoSAccountingStorageRead;

#[derive(Clone, Eq, PartialEq)]
pub struct InMemoryPoSAccounting {
    pool_addresses_balances: BTreeMap<H256, Amount>,
    delegation_to_pool_shares: BTreeMap<(H256, H256), Amount>,
    delegation_addresses_balances: BTreeMap<H256, Amount>,
    delegation_addresses_data: BTreeMap<H256, DelegationData>,
}

impl InMemoryPoSAccounting {
    pub fn new() -> Self {
        Self {
            pool_addresses_balances: Default::default(),
            delegation_to_pool_shares: Default::default(),
            delegation_addresses_balances: Default::default(),
            delegation_addresses_data: Default::default(),
        }
    }
}

impl PoSAccountingStorageRead for InMemoryPoSAccounting {
    fn get_pool_address_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        Ok(self.pool_addresses_balances.get(&pool_id).copied())
    }

    fn get_pool_delegation_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        let range_start = (pool_id, H256::zero());
        let range_end = (pool_id, H256::repeat_byte(0xFF));
        let range = self.delegation_to_pool_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    fn get_delegation_address_data(
        &self,
        delegation_address: H256,
    ) -> Result<Option<DelegationData>, Error> {
        Ok(self.delegation_addresses_data.get(&delegation_address).cloned())
    }

    fn get_delegation_address_balance(
        &self,
        delegation_address: H256,
    ) -> Result<Option<Amount>, Error> {
        Ok(self.delegation_addresses_balances.get(&delegation_address).copied())
    }
}

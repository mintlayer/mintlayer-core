use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::{
    error::Error,
    pool::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView},
    storage::PoSAccountingStorageRead,
};

use super::PoSAccounting;

impl<S: PoSAccountingStorageRead> PoSAccountingView for PoSAccounting<S> {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from)
    }

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error> {
        self.store.get_pool_data(pool_id).map_err(Error::from)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Error::from)
    }

    fn get_delegation_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_delegation_balance(delegation_id).map_err(Error::from)
    }

    fn get_delegation_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error> {
        self.store.get_delegation_data(delegation_id).map_err(Error::from)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(Error::from)
    }
}

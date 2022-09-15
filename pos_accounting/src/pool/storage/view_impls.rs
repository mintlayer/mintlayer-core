use std::collections::BTreeMap;

use common::primitives::Amount;

use crate::{
    error::Error,
    pool::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView},
    storage::PoSAccountingStorageRead,
    DelegationId, PoolId,
};

use super::PoSAccountingDBMut;

impl<'a, S: PoSAccountingStorageRead> PoSAccountingView for PoSAccountingDBMut<'a, S> {
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error> {
        self.store.get_pool_data(pool_id).map_err(Error::from)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Error::from)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error> {
        self.store.get_delegation_balance(delegation_id).map_err(Error::from)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error> {
        self.store.get_delegation_data(delegation_id).map_err(Error::from)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(Error::from)
    }
}

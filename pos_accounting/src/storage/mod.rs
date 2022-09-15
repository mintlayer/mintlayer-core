use std::collections::BTreeMap;

use common::primitives::Amount;

use crate::{
    pool::{delegation::DelegationData, pool_data::PoolData},
    DelegationId, PoolId,
};

use chainstate_types::storage_result::Error;

pub trait PoSAccountingStorageRead {
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error>;

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error>;

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error>;

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error>;
}

pub trait PoSAccountingStorageWrite: PoSAccountingStorageRead {
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> Result<(), Error>;

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), Error>;

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> Result<(), Error>;

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), Error>;

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), Error>;

    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> Result<(), Error>;

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> Result<(), Error>;

    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> Result<(), Error>;

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), Error>;

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), Error>;
}

#[cfg(test)]
pub(crate) mod in_memory;

use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::pool::{delegation::DelegationData, pool_data::PoolData};

use chainstate_types::storage_result::Error;

pub mod in_memory;

pub trait PoSAccountingStorageRead {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error>;

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error>;

    fn get_delegation_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error>;

    fn get_delegation_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error>;
}

pub trait PoSAccountingStorageWrite: PoSAccountingStorageRead {
    fn set_pool_balance(&mut self, pool_id: H256, amount: Amount) -> Result<(), Error>;

    fn del_pool_balance(&mut self, pool_id: H256) -> Result<(), Error>;

    fn set_pool_data(&mut self, pool_id: H256, pool_data: &PoolData) -> Result<(), Error>;

    fn del_pool_data(&mut self, pool_id: H256) -> Result<(), Error>;

    fn set_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount: Amount,
    ) -> Result<(), Error>;

    fn del_delegation_balance(&mut self, delegation_target: H256) -> Result<(), Error>;

    fn set_delegation_data(
        &mut self,
        delegation_id: H256,
        delegation_data: &DelegationData,
    ) -> Result<(), Error>;

    fn del_delegation_data(&mut self, delegation_id: H256) -> Result<(), Error>;

    fn set_pool_delegation_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
        amount: Amount,
    ) -> Result<(), Error>;

    fn del_pool_delegation_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<(), Error>;
}

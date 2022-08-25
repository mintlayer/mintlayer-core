use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::pool::{delegation::DelegationData, pool_data::PoolData};

use chainstate_types::storage_result::Error;

pub mod in_memory;

pub trait PoSAccountingStorageRead {
    fn get_pool_address_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error>;

    fn get_pool_delegation_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error>;

    fn get_delegation_address_data(
        &self,
        delegation_address: H256,
    ) -> Result<Option<DelegationData>, Error>;

    fn get_delegation_address_balance(
        &self,
        delegation_address: H256,
    ) -> Result<Option<Amount>, Error>;

    fn get_pool_delegation_amount(
        &self,
        pool_id: H256,
        delegation_address: H256,
    ) -> Result<Option<Amount>, Error>;

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error>;
}

pub trait PoSAccountingStorageWrite: PoSAccountingStorageRead {
    fn set_pool_address_balance(&mut self, pool_id: H256, amount: Amount) -> Result<(), Error>;

    fn del_pool_balance(&mut self, pool_id: H256) -> Result<(), Error>;

    fn set_pool_data(&mut self, pool_id: H256, pool_data: &PoolData) -> Result<(), Error>;

    fn del_pool_data(&mut self, pool_id: H256) -> Result<(), Error>;

    fn set_delegation_address_balance(
        &mut self,
        delegation_target: H256,
        amount: Amount,
    ) -> Result<(), Error>;

    fn del_delegation_address_balance(&mut self, delegation_target: H256) -> Result<(), Error>;

    fn set_pool_delegation_shares(
        &mut self,
        pool_id: H256,
        delegation_address: H256,
        amount: Amount,
    ) -> Result<(), Error>;

    fn del_pool_delegation_shares(
        &mut self,
        pool_id: H256,
        delegation_address: H256,
    ) -> Result<(), Error>;

    fn set_delegation_address_data(
        &mut self,
        delegation_address: H256,
        delegation_data: &DelegationData,
    ) -> Result<(), Error>;

    fn del_delegation_address_data(&mut self, delegation_address: H256) -> Result<(), Error>;
}

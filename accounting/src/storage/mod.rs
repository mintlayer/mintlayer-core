use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::{error::Error, pool::delegation::DelegationData};

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
}

pub trait PoSAccountingStorageWrite: PoSAccountingStorageRead {
    fn set_pool_address_balance(&mut self, pool_id: H256, amount: Amount) -> Result<(), Error>;
    fn set_pool_delegation_shares(
        &mut self,
        pool_id: H256,
        delegation_address: H256,
        amount: Amount,
    ) -> Result<(), Error>;
}

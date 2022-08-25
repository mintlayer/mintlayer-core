use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::error::Error;

use super::{delegation::DelegationData, pool_data::PoolData};

pub trait PoSAccountingView {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error>;

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error>;

    fn get_delegation_balance(&self, delegation_address: H256) -> Result<Option<Amount>, Error>;

    fn get_delegation_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_address: H256,
    ) -> Result<Option<Amount>, Error>;
}

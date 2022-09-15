use std::collections::BTreeMap;

use common::primitives::Amount;

use crate::{error::Error, DelegationId, PoolId};

use super::{delegation::DelegationData, pool_data::PoolData};

pub trait PoSAccountingView {
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error>;

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error>;

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error>;

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error>;
}

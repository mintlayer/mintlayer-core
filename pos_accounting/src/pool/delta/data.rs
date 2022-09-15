use accounting::{DeltaAmountCollection, DeltaDataCollection};

use crate::{
    pool::{delegation::DelegationData, pool_data::PoolData},
    DelegationId, PoolId,
};

use serialization::{Decode, Encode};

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct PoSAccountingDeltaData {
    pub pool_data: DeltaDataCollection<PoolId, PoolData>,
    pub pool_balances: DeltaAmountCollection<PoolId>,
    pub pool_delegation_shares: DeltaAmountCollection<(PoolId, DelegationId)>,
    pub delegation_balances: DeltaAmountCollection<DelegationId>,
    pub delegation_data: DeltaDataCollection<DelegationId, DelegationData>,
}

impl PoSAccountingDeltaData {
    pub fn new() -> Self {
        Self {
            pool_data: Default::default(),
            pool_balances: Default::default(),
            pool_delegation_shares: Default::default(),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
        }
    }
}

impl Default for PoSAccountingDeltaData {
    fn default() -> Self {
        Self::new()
    }
}

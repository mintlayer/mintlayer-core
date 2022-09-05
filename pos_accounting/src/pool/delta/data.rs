use common::primitives::H256;

use crate::pool::{delegation::DelegationData, pool_data::PoolData};

use super::{
    delta_amount_collection::DeltaAmountCollection, delta_data_collection::DeltaDataCollection,
};

use serialization::{Decode, Encode};

#[derive(Clone, Encode, Decode)]
pub struct PoSAccountingDeltaData {
    pub pool_data: DeltaDataCollection<H256, PoolData>,
    pub pool_balances: DeltaAmountCollection<H256>,
    pub pool_delegation_shares: DeltaAmountCollection<(H256, H256)>,
    pub delegation_balances: DeltaAmountCollection<H256>,
    pub delegation_data: DeltaDataCollection<H256, DelegationData>,
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

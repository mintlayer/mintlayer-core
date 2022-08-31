use std::collections::BTreeMap;

use common::primitives::{signed_amount::SignedAmount, H256};

use super::{DelegationDataDelta, PoolDataDelta};

use serialization::{Decode, Encode};

#[derive(Clone, Encode, Decode)]
pub struct PoSAccountingDeltaData {
    pub pool_data: BTreeMap<H256, PoolDataDelta>,
    pub pool_balances: BTreeMap<H256, SignedAmount>,
    pub pool_delegation_shares: BTreeMap<(H256, H256), SignedAmount>,
    pub delegation_balances: BTreeMap<H256, SignedAmount>,
    pub delegation_data: BTreeMap<H256, DelegationDataDelta>,
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

use std::collections::BTreeMap;

use common::primitives::{signed_amount::SignedAmount, Amount, H256};
use serialization::{Decode, Encode};

use crate::error::Error;

use self::combine::{combine_delegation_data, combine_pool_data, combine_signed_amount_delta};

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

mod combine;
pub mod operator_impls;
mod view_impl;

#[derive(Clone)]
#[allow(dead_code)]
enum PoolDataDelta {
    CreatePool(PoolData),
    DecommissionPool,
}

#[derive(Clone, Encode, Decode)]
#[allow(dead_code)]
enum DelegationDataDelta {
    Add(Box<DelegationData>),
    Remove,
}

#[derive(Clone)]
pub struct PoSAccountingDelta<'a> {
    parent: &'a dyn PoSAccountingView,
    pool_data: BTreeMap<H256, PoolDataDelta>,
    pool_balances: BTreeMap<H256, SignedAmount>,
    pool_delegation_shares: BTreeMap<(H256, H256), SignedAmount>,
    delegation_balances: BTreeMap<H256, SignedAmount>,
    delegation_data: BTreeMap<H256, DelegationDataDelta>,
}

impl<'a> PoSAccountingDelta<'a> {
    pub fn new(parent: &'a dyn PoSAccountingView) -> Self {
        Self {
            parent,
            pool_data: Default::default(),
            pool_balances: Default::default(),
            pool_delegation_shares: Default::default(),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
        }
    }

    fn get_cached_delegations_shares(&self, pool_id: H256) -> Option<BTreeMap<H256, SignedAmount>> {
        let range_start = (pool_id, H256::zero());
        let range_end = (pool_id, H256::repeat_byte(0xFF));
        let range = self.pool_delegation_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn merge_pool_data(&mut self, key: H256, other_data: PoolDataDelta) -> Result<(), Error> {
        let current = self.pool_data.get(&key);
        let new_data = match current {
            Some(current_data) => combine_pool_data(current_data, other_data)?,
            None => other_data,
        };
        self.pool_data.insert(key, new_data);
        Ok(())
    }

    fn merge_delegation_data(
        &mut self,
        key: H256,
        other_data: DelegationDataDelta,
    ) -> Result<(), Error> {
        let current = self.delegation_data.get(&key);
        let new_data = match current {
            Some(current_data) => combine_delegation_data(current_data, other_data)?,
            None => other_data,
        };
        self.delegation_data.insert(key, new_data);
        Ok(())
    }

    pub fn merge_with_delta(&mut self, other: PoSAccountingDelta<'a>) -> Result<(), Error> {
        other.pool_balances.into_iter().try_for_each(|(key, other_amount)| {
            merge_balance(&mut self.pool_balances, key, other_amount)
        })?;
        other
            .pool_delegation_shares
            .into_iter()
            .try_for_each(|(key, other_del_shares)| {
                merge_balance(&mut self.pool_delegation_shares, key, other_del_shares)
            })?;
        other.delegation_balances.into_iter().try_for_each(|(key, other_del_balance)| {
            merge_balance(&mut self.delegation_balances, key, other_del_balance)
        })?;
        other
            .pool_data
            .into_iter()
            .try_for_each(|(key, other_pool_data)| self.merge_pool_data(key, other_pool_data))?;
        other.delegation_data.into_iter().try_for_each(|(key, other_del_data)| {
            self.merge_delegation_data(key, other_del_data)
        })?;

        Ok(())
    }
}

fn merge_balance<T: Ord>(
    map: &mut BTreeMap<T, SignedAmount>,
    key: T,
    other_amount: SignedAmount,
) -> Result<(), Error> {
    let current = map.get(&key);
    match combine_signed_amount_delta(&current.copied(), &Some(other_amount))? {
        Some(new_bal) => map.insert(key, new_bal),
        None => None,
    };
    Ok(())
}

// TODO: this is used in both operator and view impls. Find an appropriate place for it.
fn sum_maps(
    mut m1: BTreeMap<H256, Amount>,
    m2: BTreeMap<H256, SignedAmount>,
) -> Result<BTreeMap<H256, Amount>, Error> {
    for (k, v) in m2 {
        let base_value = match m1.get(&k) {
            Some(pv) => *pv,
            None => Amount::from_atoms(0),
        };
        let base_amount = base_value.into_signed().ok_or(Error::ArithmeticErrorToUnsignedFailed)?;
        let new_amount = (base_amount + v).ok_or(Error::ArithmeticErrorSumToSignedFailed)?;
        let new_amount =
            new_amount.into_unsigned().ok_or(Error::ArithmeticErrorToUnsignedFailed)?;
        m1.insert(k, new_amount);
    }
    Ok(m1)
}

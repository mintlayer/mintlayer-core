use std::collections::BTreeMap;

use common::primitives::{signed_amount::SignedAmount, Amount, H256};
use serialization::{Decode, Encode};

use crate::error::Error;

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

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

    fn combine_pool_data(lhs: &PoolDataDelta, rhs: PoolDataDelta) -> Result<PoolDataDelta, Error> {
        match (lhs, rhs) {
            (PoolDataDelta::CreatePool(_), PoolDataDelta::CreatePool(_)) => {
                Err(Error::PoolCreatedMultipleTimes)
            }
            (PoolDataDelta::CreatePool(_), PoolDataDelta::DecommissionPool) => {
                Ok(PoolDataDelta::DecommissionPool)
            }
            (PoolDataDelta::DecommissionPool, PoolDataDelta::CreatePool(d)) => {
                Ok(PoolDataDelta::CreatePool(d))
            }
            (PoolDataDelta::DecommissionPool, PoolDataDelta::DecommissionPool) => {
                Err(Error::PoolDecommissionedMultipleTimes)
            }
        }
    }

    fn merge_pool_data(&mut self, key: H256, other_data: PoolDataDelta) -> Result<(), Error> {
        let current = self.pool_data.get(&key);
        let new_data = match current {
            Some(current_data) => Self::combine_pool_data(current_data, other_data)?,
            None => other_data,
        };
        self.pool_data.insert(key, new_data);
        Ok(())
    }

    fn combine_delegation_data(
        lhs: &DelegationDataDelta,
        rhs: DelegationDataDelta,
    ) -> Result<DelegationDataDelta, Error> {
        match (lhs, rhs) {
            (DelegationDataDelta::Add(_), DelegationDataDelta::Add(_)) => {
                Err(Error::DelegationDataCreatedMultipleTimes)
            }
            (DelegationDataDelta::Add(_), DelegationDataDelta::Remove) => {
                Ok(DelegationDataDelta::Remove)
            }
            (DelegationDataDelta::Remove, DelegationDataDelta::Add(d)) => {
                Ok(DelegationDataDelta::Add(d))
            }
            (DelegationDataDelta::Remove, DelegationDataDelta::Remove) => {
                Err(Error::DelegationDataDeletedMultipleTimes)
            }
        }
    }

    fn merge_delegation_data(
        &mut self,
        key: H256,
        other_data: DelegationDataDelta,
    ) -> Result<(), Error> {
        let current = self.delegation_data.get(&key);
        let new_data = match current {
            Some(current_data) => Self::combine_delegation_data(current_data, other_data)?,
            None => other_data,
        };
        self.delegation_data.insert(key, new_data);
        Ok(())
    }

    pub fn merge_with_delta(&mut self, other: PoSAccountingDelta<'a>) -> Result<(), Error> {
        other.pool_balances.into_iter().try_for_each(|(key, other_amount)| {
            Self::merge_balance(&mut self.pool_balances, key, other_amount)
        })?;
        other
            .pool_delegation_shares
            .into_iter()
            .try_for_each(|(key, other_del_shares)| {
                Self::merge_balance(&mut self.pool_delegation_shares, key, other_del_shares)
            })?;
        other.delegation_balances.into_iter().try_for_each(|(key, other_del_balance)| {
            Self::merge_balance(&mut self.delegation_balances, key, other_del_balance)
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

/// add two numbers that can be Some or None, one unsigned and another signed
/// If both numbers are None, then the result is none (if key not found in both parent and local)
/// If only unsigned is present, then the unsigned is returned (only parent found)
/// If only signed is present, we convert it to unsigned and return it (only delta found)
/// If both found, we add them and return them as unsigned
/// Errors can happen when doing conversions; which can uncover inconsistency issues
fn combine_amount_delta(
    lhs: &Option<Amount>,
    rhs: &Option<SignedAmount>,
) -> Result<Option<Amount>, Error> {
    match (lhs, rhs) {
        (None, None) => Ok(None),
        (None, Some(v)) => Ok(Some(
            (*v).into_unsigned().ok_or(Error::ArithmeticErrorToUnsignedFailed)?,
        )),
        (Some(v), None) => Ok(Some(*v)),
        (Some(v1), Some(v2)) => {
            let v1 = v1.into_signed().ok_or(Error::ArithmeticErrorToSignedFailed)?;
            let sum = (v1 + *v2).ok_or(Error::ArithmeticErrorDeltaAdditionFailed)?;
            let sum = sum.into_unsigned().ok_or(Error::ArithmeticErrorSumToUnsignedFailed)?;
            Ok(Some(sum))
        }
    }
}

fn combine_signed_amount_delta(
    lhs: &Option<SignedAmount>,
    rhs: &Option<SignedAmount>,
) -> Result<Option<SignedAmount>, Error> {
    match (lhs, rhs) {
        (None, None) => Ok(None),
        (None, Some(v)) => Ok(Some(*v)),
        (Some(v), None) => Ok(Some(*v)),
        (Some(v1), Some(v2)) => {
            let v1 = v1;
            let sum = (*v1 + *v2).ok_or(Error::ArithmeticErrorDeltaAdditionFailed)?;
            Ok(Some(sum))
        }
    }
}

fn signed_to_unsigned_pair((k, v): (H256, SignedAmount)) -> Result<(H256, Amount), Error> {
    let v = v.into_unsigned().ok_or(Error::ArithmeticErrorToUnsignedFailed)?;
    Ok((k, v))
}

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

impl<'a> PoSAccountingView for PoSAccountingDelta<'a> {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        let parent_balance = self.parent.get_pool_balance(pool_id)?;
        let local_delta = self.pool_balances.get(&pool_id).cloned();
        combine_amount_delta(&parent_balance, &local_delta)
    }

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error> {
        let local_data = self.pool_data.get(&pool_id);
        match local_data {
            Some(d) => match d {
                PoolDataDelta::CreatePool(d) => Ok(Some(d.clone())),
                PoolDataDelta::DecommissionPool => Ok(None),
            },
            None => self.parent.get_pool_data(pool_id),
        }
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        let parent_shares = self.parent.get_pool_delegations_shares(pool_id)?;
        let local_shares = self.get_cached_delegations_shares(pool_id);

        match (parent_shares, local_shares) {
            (None, None) => Ok(None),
            (None, Some(m)) => Ok(Some(
                m.into_iter()
                    .map(signed_to_unsigned_pair)
                    .collect::<Result<BTreeMap<H256, Amount>, Error>>()?,
            )),
            (Some(m), None) => Ok(Some(m)),
            (Some(m1), Some(m2)) => Ok(Some(sum_maps(m1, m2)?)),
        }
    }

    fn get_delegation_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_delegation_balance(delegation_id)?;
        let local_amount = self.delegation_balances.get(&delegation_id).copied();
        combine_amount_delta(&parent_amount, &local_amount)
    }

    fn get_delegation_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error> {
        let local_data = self.delegation_data.get(&delegation_id);
        match local_data {
            Some(d) => match d {
                DelegationDataDelta::Add(d) => Ok(Some(*d.clone())),
                DelegationDataDelta::Remove => Ok(None),
            },
            None => self.parent.get_delegation_data(delegation_id),
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_pool_delegation_share(pool_id, delegation_id)?;
        let local_amount = self.pool_delegation_shares.get(&(pool_id, delegation_id)).copied();
        combine_amount_delta(&parent_amount, &local_amount)
    }
}

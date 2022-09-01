use std::collections::BTreeMap;

use common::primitives::{signed_amount::SignedAmount, Amount, H256};
use serialization::{Decode, Encode};

use crate::error::Error;

use self::{
    combine::{combine_delta_data, combine_signed_amount_delta},
    data::PoSAccountingDeltaData,
};

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

mod combine;
pub mod data;
pub mod operator_impls;
mod view_impl;

#[derive(Clone, Encode, Decode)]
pub enum DataDelta<T> {
    Create(Box<T>),
    Delete,
}

#[allow(dead_code)]
pub struct DataDeltaUndo<T> {
    data: DataDelta<T>,
}

pub struct PoSAccountingDelta<'a> {
    parent: &'a dyn PoSAccountingView,
    data: PoSAccountingDeltaData,
}

#[allow(dead_code)]
pub struct DeltaMergeUndo {
    pool_data_undo: BTreeMap<H256, DataDeltaUndo<PoolData>>,
    delegation_data_undo: BTreeMap<H256, DataDeltaUndo<DelegationData>>,
}

pub enum DeltaUndoOp<T> {
    Delta(DataDelta<T>),
    Undo(DataDeltaUndo<T>),
}

impl<T> From<DataDelta<T>> for DeltaUndoOp<T> {
    fn from(v: DataDelta<T>) -> Self {
        Self::Delta(v)
    }
}

impl<T> From<DataDeltaUndo<T>> for DeltaUndoOp<T> {
    fn from(v: DataDeltaUndo<T>) -> Self {
        Self::Undo(v)
    }
}

impl<'a> PoSAccountingDelta<'a> {
    pub fn new(parent: &'a dyn PoSAccountingView) -> Self {
        Self {
            parent,
            data: PoSAccountingDeltaData::new(),
        }
    }

    pub fn from_data(parent: &'a dyn PoSAccountingView, data: PoSAccountingDeltaData) -> Self {
        Self { parent, data }
    }

    pub fn consume(self) -> PoSAccountingDeltaData {
        self.data
    }

    fn get_cached_delegations_shares(&self, pool_id: H256) -> Option<BTreeMap<H256, SignedAmount>> {
        let range_start = (pool_id, H256::zero());
        let range_end = (pool_id, H256::repeat_byte(0xFF));
        let range = self.data.pool_delegation_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn merge_delta_data<T>(
        map: &mut BTreeMap<H256, DataDelta<T>>,
        key: H256,
        other_data: DataDelta<T>,
    ) -> Result<Option<DataDeltaUndo<T>>, Error> {
        let current = map.get(&key);
        let new_data = match current {
            Some(current_data) => combine_delta_data(current_data, other_data)?,
            None => Some(other_data),
        };
        let undo = match new_data {
            Some(v) => map.insert(key, v).and(None),
            None => map.remove(&key),
        };

        Ok(undo.map(|data| DataDeltaUndo { data }))
    }

    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDelta<'a>,
    ) -> Result<DeltaMergeUndo, Error> {
        other.data.pool_balances.into_iter().try_for_each(|(key, other_amount)| {
            merge_balance(&mut self.data.pool_balances, key, other_amount)
        })?;
        other
            .data
            .pool_delegation_shares
            .into_iter()
            .try_for_each(|(key, other_del_shares)| {
                merge_balance(&mut self.data.pool_delegation_shares, key, other_del_shares)
            })?;
        other
            .data
            .delegation_balances
            .into_iter()
            .try_for_each(|(key, other_del_balance)| {
                merge_balance(&mut self.data.delegation_balances, key, other_del_balance)
            })?;

        let pool_data_undo = other
            .data
            .pool_data
            .into_iter()
            .map(|(key, other_pool_data)| {
                Self::merge_delta_data(&mut self.data.pool_data, key, other_pool_data)
                    .map(|v| (key, v))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let pool_data_undo = pool_data_undo
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect::<BTreeMap<_, _>>();

        let delegation_data_undo = other
            .data
            .delegation_data
            .into_iter()
            .map(|(key, other_del_data)| {
                Self::merge_delta_data(&mut self.data.delegation_data, key, other_del_data)
                    .map(|v| (key, v))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let delegation_data_undo = delegation_data_undo
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect::<BTreeMap<_, _>>();

        Ok(DeltaMergeUndo {
            pool_data_undo,
            delegation_data_undo,
        })
    }

    fn add_value_to_map_for_delegation<K: Ord>(
        the_map: &mut BTreeMap<K, SignedAmount>,
        key: K,
        to_add: Amount,
    ) -> Result<(), Error> {
        let signed_amount_to_add =
            to_add.into_signed().ok_or(Error::ArithmeticErrorToSignedFailed)?;
        match the_map.entry(key) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(signed_amount_to_add);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let current_amount = e.get();
                let new_amount = (*current_amount + signed_amount_to_add)
                    .ok_or(Error::DelegationBalanceAdditionError)?;
                let _ = e.insert(new_amount);
            }
        }
        Ok(())
    }

    fn sub_value_from_map_for_delegation<K: Ord>(
        the_map: &mut BTreeMap<K, SignedAmount>,
        key: K,
        to_add: Amount,
    ) -> Result<(), Error> {
        let signed_amount_to_add =
            to_add.into_signed().ok_or(Error::ArithmeticErrorToSignedFailed)?;
        match the_map.entry(key) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(signed_amount_to_add);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let current_amount = e.get();
                let new_amount = (*current_amount - signed_amount_to_add)
                    .ok_or(Error::InvariantErrorDelegationBalanceAdditionUndoError)?;
                let _ = e.insert(new_amount);
            }
        }
        Ok(())
    }

    fn add_to_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        Self::add_value_to_map_for_delegation(
            &mut self.data.delegation_balances,
            delegation_target,
            amount_to_delegate,
        )?;

        Ok(())
    }

    fn sub_from_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        Self::sub_value_from_map_for_delegation(
            &mut self.data.delegation_balances,
            delegation_target,
            amount_to_delegate,
        )?;
        Ok(())
    }

    fn add_balance_to_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        Self::add_value_to_map_for_delegation(
            &mut self.data.pool_balances,
            pool_id,
            amount_to_add,
        )?;
        Ok(())
    }

    fn sub_balance_from_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        Self::sub_value_from_map_for_delegation(
            &mut self.data.pool_balances,
            pool_id,
            amount_to_add,
        )?;
        Ok(())
    }

    fn add_delegation_to_pool_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        Self::add_value_to_map_for_delegation(
            &mut self.data.pool_delegation_shares,
            (pool_id, delegation_id),
            amount_to_add,
        )?;
        Ok(())
    }

    fn sub_delegation_from_pool_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        Self::sub_value_from_map_for_delegation(
            &mut self.data.pool_delegation_shares,
            (pool_id, delegation_id),
            amount_to_add,
        )?;
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

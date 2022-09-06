use std::collections::BTreeMap;

use common::primitives::{signed_amount::SignedAmount, Amount, H256};

use crate::error::Error;

use self::{data::PoSAccountingDeltaData, delta_data_collection::undo::DeltaDataUndoCollection};

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

mod combine;
pub mod data;
pub mod delta_amount_collection;
pub mod delta_data_collection;
pub mod operator_impls;
mod view_impl;

pub struct PoSAccountingDelta<'a> {
    parent: &'a dyn PoSAccountingView,
    data: PoSAccountingDeltaData,
}

/// All the operations we have to do with the accounting state to undo a delta
#[allow(dead_code)]
pub struct DeltaMergeUndo {
    pool_data_undo: DeltaDataUndoCollection<H256, PoolData>,
    delegation_data_undo: DeltaDataUndoCollection<H256, DelegationData>,
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

    pub fn data(&self) -> &PoSAccountingDeltaData {
        &self.data
    }

    pub fn is_empty(&self) -> bool {
        self.data.pool_balances.data().is_empty()
            && self.data.pool_data.data().is_empty()
            && self.data.delegation_balances.data().is_empty()
            && self.data.delegation_data.data().is_empty()
            && self.data.pool_delegation_shares.data().is_empty()
    }

    fn get_cached_delegations_shares(&self, pool_id: H256) -> Option<BTreeMap<H256, SignedAmount>> {
        let range_start = (pool_id, H256::zero());
        let range_end = (pool_id, H256::repeat_byte(0xFF));
        let range = self.data.pool_delegation_shares.data().range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    pub fn undo_delta_merge(
        &mut self,
        already_merged: PoSAccountingDeltaData,
        undo_data: DeltaMergeUndo,
    ) -> Result<(), Error> {
        self.data.pool_balances.undo_merge_delta_amounts(already_merged.pool_balances)?;

        self.data
            .pool_delegation_shares
            .undo_merge_delta_amounts(already_merged.pool_delegation_shares)?;

        self.data
            .delegation_balances
            .undo_merge_delta_amounts(already_merged.delegation_balances)?;

        self.data.pool_data.undo_merge_delta_data(undo_data.pool_data_undo)?;

        self.data
            .delegation_data
            .undo_merge_delta_data(undo_data.delegation_data_undo)?;

        Ok(())
    }

    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Error> {
        self.data.pool_balances.merge_delta_amounts(other.pool_balances)?;

        self.data
            .pool_delegation_shares
            .merge_delta_amounts(other.pool_delegation_shares)?;

        self.data.delegation_balances.merge_delta_amounts(other.delegation_balances)?;

        let pool_data_undo = self.data.pool_data.merge_delta_data(other.pool_data)?;

        let delegation_data_undo =
            self.data.delegation_data.merge_delta_data(other.delegation_data)?;

        Ok(DeltaMergeUndo {
            pool_data_undo,
            delegation_data_undo,
        })
    }

    fn add_to_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        self.data
            .delegation_balances
            .add_unsigned(delegation_target, amount_to_delegate)
    }

    fn sub_from_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        self.data
            .delegation_balances
            .sub_unsigned(delegation_target, amount_to_delegate)
    }

    fn add_balance_to_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        self.data.pool_balances.add_unsigned(pool_id, amount_to_add)
    }

    fn sub_balance_from_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        self.data.pool_balances.sub_unsigned(pool_id, amount_to_add)
    }

    fn add_delegation_to_pool_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        self.data
            .pool_delegation_shares
            .add_unsigned((pool_id, delegation_id), amount_to_add)
    }

    fn sub_delegation_from_pool_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        self.data
            .pool_delegation_shares
            .sub_unsigned((pool_id, delegation_id), amount_to_add)
    }
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

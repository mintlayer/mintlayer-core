use std::{collections::BTreeMap, ops::Neg};

use accounting::{combine_amount_delta, combine_data_with_delta, DeltaDataCollection};
use chainstate_types::storage_result;
use common::primitives::{signed_amount::SignedAmount, Amount, H256};

use crate::{
    error::Error,
    pool::delta::data::PoSAccountingDeltaData,
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
};

use super::{delegation::DelegationData, pool_data::PoolData};

pub mod operator_impls;
pub mod view_impls;

mod helpers;
use helpers::BorrowedStorageValue;

pub struct PoSAccountingDBMut<'a, S> {
    store: &'a mut S,
}

impl<'a, S> PoSAccountingDBMut<'a, S> {
    pub fn new_empty(store: &'a mut S) -> Self {
        Self { store }
    }
}

pub struct DataMergeUndo {
    pool_data_undo: BTreeMap<H256, Option<PoolData>>,
    delegation_data_undo: BTreeMap<H256, Option<DelegationData>>,
}

impl<'a, S: PoSAccountingStorageWrite> PoSAccountingDBMut<'a, S> {
    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
    ) -> Result<DataMergeUndo, Error> {
        let pool_data_undo = self.merge_data_generic(
            other.pool_data,
            |s, id| s.get_pool_data(id),
            |s, id, data| s.set_pool_data(id, data),
            |s, id| s.del_pool_data(id),
        )?;

        let delegation_data_undo = self.merge_data_generic(
            other.delegation_data,
            |s, id| s.get_delegation_data(id),
            |s, id, data| s.set_delegation_data(id, data),
            |s, id| s.del_delegation_data(id),
        )?;

        self.merge_balances_generic(
            other.pool_balances.consume().into_iter(),
            |s, id| s.get_pool_balance(id),
            |s, id, amount| s.set_pool_balance(id, amount),
            |s, id| s.del_pool_balance(id),
        )?;

        self.merge_balances_generic(
            other.delegation_balances.consume().into_iter(),
            |s, id| s.get_delegation_balance(id),
            |s, id, amount| s.set_delegation_balance(id, amount),
            |s, id| s.del_delegation_balance(id),
        )?;

        self.merge_balances_generic(
            other.pool_delegation_shares.consume().into_iter(),
            |s, (pool_id, delegation_id)| s.get_pool_delegation_share(pool_id, delegation_id),
            |s, (pool_id, delegation_id), amount| {
                s.set_pool_delegation_share(pool_id, delegation_id, amount)
            },
            |s, (pool_id, delegation_id)| s.del_pool_delegation_share(pool_id, delegation_id),
        )?;

        Ok(DataMergeUndo {
            pool_data_undo,
            delegation_data_undo,
        })
    }

    pub fn undo_merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
        undo: DataMergeUndo,
    ) -> Result<(), Error> {
        self.undo_merge_data_generic(
            undo.pool_data_undo.into_iter(),
            |_, _| unreachable!(),
            |s, id, data| s.set_pool_data(id, data),
            |s, id| s.del_pool_data(id),
        )?;

        self.undo_merge_data_generic(
            undo.delegation_data_undo.into_iter(),
            |_, _| unreachable!(),
            |s, id, data| s.set_delegation_data(id, data),
            |s, id| s.del_delegation_data(id),
        )?;

        self.merge_balances_generic(
            other
                .pool_balances
                .consume()
                .into_iter()
                .map(|(k, v)| (k, v.neg().expect("amount negation some"))),
            |s, id| s.get_pool_balance(id),
            |s, id, amount| s.set_pool_balance(id, amount),
            |s, id| s.del_pool_balance(id),
        )?;

        self.merge_balances_generic(
            other
                .delegation_balances
                .consume()
                .into_iter()
                .map(|(k, v)| (k, v.neg().expect("amount negation some"))),
            |s, id| s.get_delegation_balance(id),
            |s, id, amount| s.set_delegation_balance(id, amount),
            |s, id| s.del_delegation_balance(id),
        )?;

        self.merge_balances_generic(
            other
                .pool_delegation_shares
                .consume()
                .into_iter()
                .map(|(k, v)| (k, v.neg().expect("amount negation some"))),
            |s, (pool_id, delegation_id)| s.get_pool_delegation_share(pool_id, delegation_id),
            |s, (pool_id, delegation_id), amount| {
                s.set_pool_delegation_share(pool_id, delegation_id, amount)
            },
            |s, (pool_id, delegation_id)| s.del_pool_delegation_share(pool_id, delegation_id),
        )?;

        Ok(())
    }

    fn merge_balances_generic<Iter, K: Ord + Copy, Getter, Setter, Deleter>(
        &mut self,
        mut iter: Iter,
        getter: Getter,
        setter: Setter,
        deleter: Deleter,
    ) -> Result<(), Error>
    where
        Iter: Iterator<Item = (K, SignedAmount)>,
        Getter: Fn(&S, K) -> Result<Option<Amount>, storage_result::Error>,
        Setter: FnMut(&mut S, K, Amount) -> Result<(), storage_result::Error>,
        Deleter: FnMut(&mut S, K) -> Result<(), storage_result::Error>,
    {
        let mut store = BorrowedStorageValue::new(self.store, getter, setter, deleter);
        iter.try_for_each(|(id, delta)| -> Result<(), Error> {
            let balance = store.get(id)?;
            match combine_amount_delta(&balance, &Some(delta))? {
                Some(result) => {
                    if result > Amount::ZERO {
                        store.set(id, result)?
                    } else {
                        store.delete(id)?
                    }
                }
                None => store.delete(id)?,
            }
            Ok(())
        })
    }

    fn merge_data_generic<K: Ord + Copy, T: Clone, Getter, Setter, Deleter>(
        &mut self,
        delta: DeltaDataCollection<K, T>,
        getter: Getter,
        setter: Setter,
        deleter: Deleter,
    ) -> Result<BTreeMap<K, Option<T>>, Error>
    where
        Getter: Fn(&S, K) -> Result<Option<T>, storage_result::Error>,
        Setter: FnMut(&mut S, K, &T) -> Result<(), storage_result::Error>,
        Deleter: FnMut(&mut S, K) -> Result<(), storage_result::Error>,
    {
        let mut store = BorrowedStorageValue::new(self.store, getter, setter, deleter);
        delta
            .data()
            .iter()
            .map(|(id, delta)| -> Result<_, Error> {
                let data = store.get(*id)?;
                match combine_data_with_delta(data.as_ref(), Some(delta))? {
                    Some(result) => store.set(*id, &result)?,
                    None => store.delete(*id)?,
                }
                Ok((*id, data))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    fn undo_merge_data_generic<K: Ord + Copy, T: Clone, Iter, Getter, Setter, Deleter>(
        &mut self,
        mut iter: Iter,
        getter: Getter,
        setter: Setter,
        deleter: Deleter,
    ) -> Result<(), Error>
    where
        Iter: Iterator<Item = (K, Option<T>)>,
        Getter: Fn(&S, K) -> Result<Option<T>, storage_result::Error>,
        Setter: FnMut(&mut S, K, &T) -> Result<(), storage_result::Error>,
        Deleter: FnMut(&mut S, K) -> Result<(), storage_result::Error>,
    {
        let mut store = BorrowedStorageValue::new(self.store, getter, setter, deleter);
        iter.try_for_each(|(key, undo_data)| match undo_data {
            Some(data) => store.set(key, &data),
            None => store.delete(key),
        })
    }

    fn add_to_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let current_amount =
            self.store.get_delegation_balance(delegation_target)?.unwrap_or(Amount::ZERO);
        let new_amount =
            (current_amount + amount_to_delegate).ok_or(Error::DelegationBalanceAdditionError)?;
        self.store.set_delegation_balance(delegation_target, new_amount)?;
        Ok(())
    }

    fn sub_from_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .store
            .get_delegation_balance(delegation_target)?
            .ok_or(Error::DelegateToNonexistingId)?;
        let new_amount = (current_amount - amount_to_delegate)
            .ok_or(Error::DelegationBalanceSubtractionError)?;
        if new_amount == Amount::ZERO {
            self.store.del_delegation_balance(delegation_target)?;
        } else {
            self.store.set_delegation_balance(delegation_target, new_amount)?;
        }
        Ok(())
    }

    fn add_balance_to_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        let pool_amount =
            self.store.get_pool_balance(pool_id)?.ok_or(Error::DelegateToNonexistingPool)?;
        let new_amount = (pool_amount + amount_to_add).ok_or(Error::PoolBalanceAdditionError)?;
        self.store.set_pool_balance(pool_id, new_amount)?;
        Ok(())
    }

    fn sub_balance_from_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        let pool_amount =
            self.store.get_pool_balance(pool_id)?.ok_or(Error::DelegateToNonexistingPool)?;
        let new_amount = (pool_amount - amount_to_add).ok_or(Error::PoolBalanceSubtractionError)?;
        if new_amount == Amount::ZERO {
            self.store.del_pool_balance(pool_id)?;
        } else {
            self.store.set_pool_balance(pool_id, new_amount)?;
        }
        Ok(())
    }

    fn add_delegation_to_pool_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .store
            .get_pool_delegation_share(pool_id, delegation_id)?
            .unwrap_or(Amount::ZERO);
        let new_amount =
            (current_amount + amount_to_add).ok_or(Error::DelegationSharesAdditionError)?;
        self.store.set_pool_delegation_share(pool_id, delegation_id, new_amount)?;
        Ok(())
    }

    fn sub_delegation_from_pool_share(
        &mut self,
        pool_id: H256,
        delegation_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .store
            .get_pool_delegation_share(pool_id, delegation_id)?
            .ok_or(Error::InvariantErrorDelegationShareNotFound)?;
        let new_amount =
            (current_amount - amount_to_add).ok_or(Error::DelegationSharesSubtractionError)?;
        if new_amount > Amount::ZERO {
            self.store.set_pool_delegation_share(pool_id, delegation_id, new_amount)?;
        } else {
            self.store.del_pool_delegation_share(pool_id, delegation_id)?;
        }
        Ok(())
    }
}

impl<'a, S: PoSAccountingStorageRead> PoSAccountingDBMut<'a, S> {
    fn get_delegation_data(&self, delegation_target: H256) -> Result<DelegationData, Error> {
        let delegation_target = self
            .store
            .get_delegation_data(delegation_target)
            .map_err(Error::from)?
            .ok_or(Error::DelegateToNonexistingId)?;
        Ok(delegation_target)
    }
}

// TODO: add unit tests for merge_balances_generic and merge_data_generic

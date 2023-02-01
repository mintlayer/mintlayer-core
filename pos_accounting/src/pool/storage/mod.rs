// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{collections::BTreeMap, ops::Neg};

use accounting::{
    combine_amount_delta, combine_data_with_delta, DeltaAmountCollection, DeltaDataCollection,
    DeltaDataUndoCollection,
};
use chainstate_types::storage_result;
use common::primitives::{signed_amount::SignedAmount, Amount};

use crate::{
    error::Error, pool::delta::data::PoSAccountingDeltaData, storage::PoSAccountingStorageWrite,
    DelegationId, DeltaMergeUndo, PoolId,
};

pub mod operator_impls;
pub mod view_impls;

mod helpers;
use helpers::BorrowedStorageValue;

pub struct PoSAccountingDB<S> {
    store: S,
}

impl<S> PoSAccountingDB<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: PoSAccountingStorageWrite> PoSAccountingDB<S> {
    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Error> {
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

        let pool_balances_undo = self.merge_balances_generic(
            other.pool_balances.consume().into_iter(),
            |s, id| s.get_pool_balance(id),
            |s, id, amount| s.set_pool_balance(id, amount),
            |s, id| s.del_pool_balance(id),
        )?;

        let delegation_balances_undo = self.merge_balances_generic(
            other.delegation_balances.consume().into_iter(),
            |s, id| s.get_delegation_balance(id),
            |s, id, amount| s.set_delegation_balance(id, amount),
            |s, id| s.del_delegation_balance(id),
        )?;

        let pool_delegation_shares_undo = self.merge_balances_generic(
            other.pool_delegation_shares.consume().into_iter(),
            |s, (pool_id, delegation_id)| s.get_pool_delegation_share(pool_id, delegation_id),
            |s, (pool_id, delegation_id), amount| {
                s.set_pool_delegation_share(pool_id, delegation_id, amount)
            },
            |s, (pool_id, delegation_id)| s.del_pool_delegation_share(pool_id, delegation_id),
        )?;

        Ok(DeltaMergeUndo {
            pool_data_undo,
            delegation_data_undo,
            pool_balances_undo,
            pool_delegation_shares_undo,
            delegation_balances_undo,
        })
    }

    pub fn undo_merge_with_delta(&mut self, undo: DeltaMergeUndo) -> Result<(), Error> {
        self.undo_merge_data_generic(
            undo.pool_data_undo,
            |s, id| s.get_pool_data(id),
            |s, id, data| s.set_pool_data(id, data),
            |s, id| s.del_pool_data(id),
        )?;

        self.undo_merge_data_generic(
            undo.delegation_data_undo,
            |s, id| s.get_delegation_data(id),
            |s, id, data| s.set_delegation_data(id, data),
            |s, id| s.del_delegation_data(id),
        )?;

        self.merge_balances_generic(
            undo.pool_balances_undo.consume().into_iter(),
            |s, id| s.get_pool_balance(id),
            |s, id, amount| s.set_pool_balance(id, amount),
            |s, id| s.del_pool_balance(id),
        )?;

        self.merge_balances_generic(
            undo.delegation_balances_undo.consume().into_iter(),
            |s, id| s.get_delegation_balance(id),
            |s, id, amount| s.set_delegation_balance(id, amount),
            |s, id| s.del_delegation_balance(id),
        )?;

        self.merge_balances_generic(
            undo.pool_delegation_shares_undo.consume().into_iter(),
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
        iter: Iter,
        getter: Getter,
        setter: Setter,
        deleter: Deleter,
    ) -> Result<DeltaAmountCollection<K>, Error>
    where
        Iter: Iterator<Item = (K, SignedAmount)>,
        Getter: Fn(&S, K) -> Result<Option<Amount>, storage_result::Error>,
        Setter: FnMut(&mut S, K, Amount) -> Result<(), storage_result::Error>,
        Deleter: FnMut(&mut S, K) -> Result<(), storage_result::Error>,
    {
        let mut store = BorrowedStorageValue::new(&mut self.store, getter, setter, deleter);
        let undo = iter
            .map(|(id, delta)| -> Result<_, Error> {
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
                };
                let balance_undo = delta.neg().expect("amount negation some");
                Ok((id, balance_undo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(DeltaAmountCollection::from_iter(undo.into_iter()))
    }

    fn merge_data_generic<K: Ord + Copy, T: Clone + Eq, Getter, Setter, Deleter>(
        &mut self,
        delta: DeltaDataCollection<K, T>,
        getter: Getter,
        setter: Setter,
        deleter: Deleter,
    ) -> Result<DeltaDataUndoCollection<K, T>, Error>
    where
        Getter: Fn(&S, K) -> Result<Option<T>, storage_result::Error>,
        Setter: FnMut(&mut S, K, &T) -> Result<(), storage_result::Error>,
        Deleter: FnMut(&mut S, K) -> Result<(), storage_result::Error>,
    {
        let mut store = BorrowedStorageValue::new(&mut self.store, getter, setter, deleter);
        let undo = delta
            .consume()
            .into_iter()
            .map(|(id, delta)| -> Result<_, Error> {
                let undo = delta.clone().invert();
                let old_data = store.get(id)?;
                match combine_data_with_delta(old_data.clone(), Some(delta))? {
                    Some(result) => store.set(id, &result)?,
                    None => store.delete(id)?,
                };
                Ok((id, undo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(DeltaDataUndoCollection::new(undo))
    }

    fn undo_merge_data_generic<K: Ord + Copy, T: Clone + Eq, Getter, Setter, Deleter>(
        &mut self,
        undo: DeltaDataUndoCollection<K, T>,
        getter: Getter,
        setter: Setter,
        deleter: Deleter,
    ) -> Result<(), Error>
    where
        Getter: Fn(&S, K) -> Result<Option<T>, storage_result::Error>,
        Setter: FnMut(&mut S, K, &T) -> Result<(), storage_result::Error>,
        Deleter: FnMut(&mut S, K) -> Result<(), storage_result::Error>,
    {
        let mut store = BorrowedStorageValue::new(&mut self.store, getter, setter, deleter);
        undo.consume().into_iter().try_for_each(|(id, delta)| {
            let old_data = store.get(id)?;
            match combine_data_with_delta(old_data.clone(), Some(delta.consume()))? {
                Some(result) => store.set(id, &result)?,
                None => store.delete(id)?,
            };
            Ok(())
        })
    }

    fn add_to_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
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
        delegation_target: DelegationId,
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

    fn add_balance_to_pool(&mut self, pool_id: PoolId, amount_to_add: Amount) -> Result<(), Error> {
        let pool_amount =
            self.store.get_pool_balance(pool_id)?.ok_or(Error::DelegateToNonexistingPool)?;
        let new_amount = (pool_amount + amount_to_add).ok_or(Error::PoolBalanceAdditionError)?;
        self.store.set_pool_balance(pool_id, new_amount)?;
        Ok(())
    }

    fn sub_balance_from_pool(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
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
        pool_id: PoolId,
        delegation_id: DelegationId,
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
        pool_id: PoolId,
        delegation_id: DelegationId,
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

// TODO: add unit tests for merge_balances_generic and merge_data_generic

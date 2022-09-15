use std::collections::BTreeMap;

use accounting::{
    combine_amount_delta, combine_data_with_delta, DeltaAmountCollection, DeltaDataCollection,
};
use common::primitives::{Amount, H256};

use crate::{
    error::Error,
    pool::delta::data::PoSAccountingDeltaData,
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
};

use super::{delegation::DelegationData, pool_data::PoolData};

pub mod operator_impls;
pub mod view_impls;

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
    pool_balances_undo: BTreeMap<H256, Option<Amount>>,
    pool_delegation_shares_undo: BTreeMap<(H256, H256), Option<Amount>>,
    delegation_balances_undo: BTreeMap<H256, Option<Amount>>,
}

impl<'a, S: PoSAccountingStorageWrite> PoSAccountingDBMut<'a, S> {
    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
    ) -> Result<DataMergeUndo, Error> {
        let pool_data_undo = self.merge_pool_data(other.pool_data)?;
        let delegation_data_undo = self.merge_delegation_data(other.delegation_data)?;
        let pool_balances_undo = self.merge_pool_balances_with_delta(other.pool_balances)?;
        let pool_delegation_shares_undo =
            self.merge_delegation_shares_with_delta(other.pool_delegation_shares)?;
        let delegation_balances_undo = self.merge_delegation_balances(other.delegation_balances)?;

        Ok(DataMergeUndo {
            pool_data_undo,
            delegation_data_undo,
            pool_balances_undo,
            pool_delegation_shares_undo,
            delegation_balances_undo,
        })
    }

    fn merge_pool_balances_with_delta(
        &mut self,
        delta: DeltaAmountCollection<H256>,
    ) -> Result<BTreeMap<H256, Option<Amount>>, Error> {
        delta
            .data()
            .iter()
            .map(|(pool_id, delta)| -> Result<_, Error> {
                let pool_balance = self.store.get_pool_balance(*pool_id)?;
                match combine_amount_delta(&pool_balance, &Some(*delta))? {
                    Some(result) => self.store.set_pool_balance(*pool_id, result)?,
                    None => self.store.del_pool_balance(*pool_id)?,
                }
                Ok((*pool_id, pool_balance))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    fn merge_delegation_shares_with_delta(
        &mut self,
        delta: DeltaAmountCollection<(H256, H256)>,
    ) -> Result<BTreeMap<(H256, H256), Option<Amount>>, Error> {
        delta
            .data()
            .iter()
            .map(|((pool_id, delegation_id), delta)| -> Result<_, Error> {
                let delegation_share =
                    self.store.get_pool_delegation_share(*pool_id, *delegation_id)?;
                match combine_amount_delta(&delegation_share, &Some(*delta))? {
                    Some(result) => {
                        self.store.set_pool_delegation_share(*pool_id, *delegation_id, result)?
                    }
                    None => self.store.del_pool_delegation_share(*pool_id, *delegation_id)?,
                }
                Ok(((*pool_id, *delegation_id), delegation_share))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    fn merge_delegation_balances(
        &mut self,
        delta: DeltaAmountCollection<H256>,
    ) -> Result<BTreeMap<H256, Option<Amount>>, Error> {
        delta
            .data()
            .iter()
            .map(|(delegation_id, delta)| -> Result<_, Error> {
                let delegation_balance = self.store.get_delegation_balance(*delegation_id)?;
                match combine_amount_delta(&delegation_balance, &Some(*delta))? {
                    Some(result) => self.store.set_delegation_balance(*delegation_id, result)?,
                    None => self.store.del_delegation_balance(*delegation_id)?,
                }
                Ok((*delegation_id, delegation_balance))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    fn merge_pool_data(
        &mut self,
        delta: DeltaDataCollection<H256, PoolData>,
    ) -> Result<BTreeMap<H256, Option<PoolData>>, Error> {
        delta
            .data()
            .iter()
            .map(|(pool_id, delta)| -> Result<_, Error> {
                let pool_data = self.store.get_pool_data(*pool_id)?;
                match combine_data_with_delta(pool_data.as_ref(), Some(delta))? {
                    Some(result) => self.store.set_pool_data(*pool_id, &result)?,
                    None => self.store.del_pool_data(*pool_id)?,
                }
                Ok((*pool_id, pool_data))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    fn merge_delegation_data(
        &mut self,
        delta: DeltaDataCollection<H256, DelegationData>,
    ) -> Result<BTreeMap<H256, Option<DelegationData>>, Error> {
        delta
            .data()
            .iter()
            .map(|(delegation_id, delta)| -> Result<_, Error> {
                let delegation_data = self.store.get_delegation_data(*delegation_id)?;
                match combine_data_with_delta(delegation_data.as_ref(), Some(delta))? {
                    Some(result) => self.store.set_delegation_data(*delegation_id, &result)?,
                    None => self.store.del_delegation_data(*delegation_id)?,
                }
                Ok((*delegation_id, delegation_data))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    pub fn undo_merge_with_delta(&mut self, other: DataMergeUndo) -> Result<(), Error> {
        other.pool_data_undo.iter().try_for_each(|(key, undo_data)| match undo_data {
            Some(data) => self.store.set_pool_data(*key, data),
            None => self.store.del_pool_data(*key),
        })?;

        other
            .delegation_data_undo
            .iter()
            .try_for_each(|(key, undo_data)| match undo_data {
                Some(data) => self.store.set_delegation_data(*key, data),
                None => self.store.del_delegation_data(*key),
            })?;

        other
            .pool_balances_undo
            .iter()
            .try_for_each(|(key, undo_data)| match undo_data {
                Some(amount) => self.store.set_pool_balance(*key, *amount),
                None => self.store.del_pool_balance(*key),
            })?;

        other
            .delegation_balances_undo
            .iter()
            .try_for_each(|(key, undo_data)| match undo_data {
                Some(amount) => self.store.set_delegation_balance(*key, *amount),
                None => self.store.del_delegation_balance(*key),
            })?;

        other.pool_delegation_shares_undo.iter().try_for_each(
            |((pool_id, delegation_id), undo_data)| match undo_data {
                Some(amount) => {
                    self.store.set_pool_delegation_share(*pool_id, *delegation_id, *amount)
                }
                None => self.store.del_pool_delegation_share(*pool_id, *delegation_id),
            },
        )?;
        Ok(())
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

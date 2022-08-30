use common::primitives::{Amount, H256};

use crate::{
    error::Error,
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
};

use super::delegation::DelegationData;

pub mod operator_impls;
pub mod view_impls;

pub struct PoSAccounting<S> {
    store: S,
}

impl<S> PoSAccounting<S> {
    pub fn new_empty(store: S) -> Self {
        Self { store }
    }
}

impl<S: PoSAccountingStorageWrite> PoSAccounting<S> {
    fn add_to_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .store
            .get_delegation_balance(delegation_target)?
            .ok_or(Error::DelegateToNonexistingId)?;
        let new_amount =
            (current_amount + amount_to_delegate).ok_or(Error::DelegationBalanceAdditionError)?;
        self.store.set_delegation_balance(delegation_target, new_amount)?;
        Ok(())
    }

    fn undo_add_to_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .store
            .get_delegation_balance(delegation_target)?
            .ok_or(Error::DelegateToNonexistingId)?;
        let new_amount =
            (current_amount - amount_to_delegate).ok_or(Error::DelegationBalanceAdditionError)?;
        self.store.set_delegation_balance(delegation_target, new_amount)?;
        Ok(())
    }

    fn add_balance_to_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        let pool_amount =
            self.store.get_pool_balance(pool_id)?.ok_or(Error::DelegateToNonexistingPool)?;
        let new_amount = (pool_amount + amount_to_add).ok_or(Error::PoolBalanceAdditionError)?;
        self.store.set_pool_balance(pool_id, new_amount)?;
        Ok(())
    }

    fn undo_add_balance_to_pool(
        &mut self,
        pool_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        let pool_amount =
            self.store.get_pool_balance(pool_id)?.ok_or(Error::DelegateToNonexistingPool)?;
        let new_amount = (pool_amount - amount_to_add).ok_or(Error::PoolBalanceAdditionError)?;
        self.store.set_pool_balance(pool_id, new_amount)?;
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
            .unwrap_or(Amount::from_atoms(0));
        let new_amount =
            (current_amount + amount_to_add).ok_or(Error::DelegationSharesAdditionError)?;
        self.store.set_pool_delegation_share(pool_id, delegation_id, new_amount)?;
        Ok(())
    }

    fn undo_add_delegation_to_pool_share(
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
            (current_amount + amount_to_add).ok_or(Error::DelegationSharesAdditionError)?;
        if new_amount > Amount::from_atoms(0) {
            self.store.set_pool_delegation_share(pool_id, delegation_id, new_amount)?;
        } else {
            self.store.del_pool_delegation_share(pool_id, delegation_id)?;
        }
        Ok(())
    }
}

impl<S: PoSAccountingStorageRead> PoSAccounting<S> {
    fn get_delegation_data(&self, delegation_target: H256) -> Result<DelegationData, Error> {
        let delegation_target = self
            .store
            .get_delegation_data(delegation_target)
            .map_err(Error::from)?
            .ok_or(Error::DelegateToNonexistingId)?;
        Ok(delegation_target)
    }
}

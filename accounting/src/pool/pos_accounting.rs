use std::collections::BTreeMap;

use common::{
    chain::OutPoint,
    primitives::{Amount, H256},
};
use crypto::key::PublicKey;

use crate::{
    error::Error,
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
};

use super::{
    delegation::DelegationData,
    helpers::{make_delegation_id, make_pool_id},
    pool_data::PoolData,
    view::PoSAccountingView,
};

pub struct CreatePoolUndo {
    input0_outpoint: OutPoint,
    pledge_amount: Amount,
}

pub struct CreateDelegationIdUndo {
    delegation_data: DelegationData,
    input0_outpoint: OutPoint,
}

pub struct DecommissionPoolUndo {
    pool_id: H256,
    last_amount: Amount,
    pool_data: PoolData,
}

pub struct DelegateStakingUndo {
    delegation_target: H256,
    amount_to_delegate: Amount,
}

pub enum PoSAccountingUndo {
    CreatePool(CreatePoolUndo),
    DecommissionPool(DecommissionPoolUndo),
    CreateDelegationId(CreateDelegationIdUndo),
    DelegateStaking(DelegateStakingUndo),
}

pub struct PoSAccounting<S> {
    store: S,
}

impl<S> PoSAccounting<S> {
    pub fn new_empty(store: S) -> Self {
        Self { store }
    }
}

impl<S: PoSAccountingStorageWrite> PoSAccounting<S> {
    pub fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
        decommission_key: PublicKey,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_id = make_pool_id(input0_outpoint);

        {
            let current_amount = self.store.get_pool_balance(pool_id)?;
            if current_amount.is_some() {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolBalanceAlreadyExists);
            }
        }

        {
            let current_data = self.store.get_pool_data(pool_id)?;
            if current_data.is_some() {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolDataAlreadyExists);
            }
        }

        self.store.set_pool_balance(pool_id, pledge_amount)?;
        self.store.set_pool_data(pool_id, &PoolData::new(decommission_key.clone()))?;

        Ok(PoSAccountingUndo::CreatePool(CreatePoolUndo {
            input0_outpoint: input0_outpoint.clone(),
            pledge_amount,
        }))
    }

    pub fn undo_create_pool(&mut self, undo_data: CreatePoolUndo) -> Result<(), Error> {
        let pool_id = make_pool_id(&undo_data.input0_outpoint);

        let amount = self.store.get_pool_balance(pool_id)?;

        match amount {
            Some(amount) => {
                if amount != undo_data.pledge_amount {
                    return Err(Error::InvariantErrorPoolCreationReversalFailedAmountChanged);
                }
            }
            None => return Err(Error::InvariantErrorPoolCreationReversalFailedBalanceNotFound),
        }

        let pool_data = self.store.get_pool_data(pool_id)?;
        {
            if pool_data.is_none() {
                return Err(Error::InvariantErrorPoolCreationReversalFailedDataNotFound);
            }
        }

        self.store.del_pool_balance(pool_id)?;
        self.store.del_pool_data(pool_id)?;

        Ok(())
    }

    pub fn decommission_pool(&mut self, pool_id: H256) -> Result<PoSAccountingUndo, Error> {
        let last_amount = self
            .store
            .get_pool_balance(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolBalance)?;

        let pool_data = self
            .store
            .get_pool_data(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolData)?;

        self.store.del_pool_balance(pool_id)?;
        self.store.del_pool_data(pool_id)?;

        Ok(PoSAccountingUndo::DecommissionPool(DecommissionPoolUndo {
            pool_id,
            last_amount,
            pool_data,
        }))
    }

    pub fn undo_decommission_pool(&mut self, undo_data: DecommissionPoolUndo) -> Result<(), Error> {
        let current_amount = self.store.get_pool_balance(undo_data.pool_id)?;
        if current_amount.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists);
        }

        let current_data = self.store.get_pool_data(undo_data.pool_id)?;
        if current_data.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists);
        }

        self.store.set_pool_balance(undo_data.pool_id, undo_data.last_amount)?;
        self.store.set_pool_data(undo_data.pool_id, &undo_data.pool_data)?;

        Ok(())
    }

    pub fn create_delegation_id(
        &mut self,
        target_pool: H256,
        spend_key: PublicKey,
        input0_outpoint: &OutPoint,
    ) -> Result<(H256, PoSAccountingUndo), Error> {
        if !self.pool_exists(target_pool)? {
            return Err(Error::DelegationCreationFailedPoolDoesNotExist);
        }

        let delegation_id = make_delegation_id(input0_outpoint);

        {
            let current_delegation_data = self.store.get_delegation_data(delegation_id)?;
            if current_delegation_data.is_some() {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorDelegationCreationFailedIdAlreadyExists);
            }
        }

        let delegation_data = DelegationData::new(target_pool, spend_key);

        self.store.set_delegation_data(delegation_id, &delegation_data)?;

        Ok((
            delegation_id,
            PoSAccountingUndo::CreateDelegationId(CreateDelegationIdUndo {
                delegation_data,
                input0_outpoint: input0_outpoint.clone(),
            }),
        ))
    }

    pub fn undo_create_delegation_id(
        &mut self,
        undo_data: CreateDelegationIdUndo,
    ) -> Result<(), Error> {
        let delegation_id = make_delegation_id(&undo_data.input0_outpoint);

        let removed_data = self
            .store
            .get_delegation_data(delegation_id)?
            .ok_or(Error::InvariantErrorDelegationIdUndoFailedNotFound)?;

        if removed_data != undo_data.delegation_data {
            return Err(Error::InvariantErrorDelegationIdUndoFailedDataConflict);
        }

        self.store.del_delegation_data(delegation_id)?;

        Ok(())
    }

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

    pub fn delegate_staking(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_id = *self.get_delegation_data(delegation_target)?.source_pool();

        self.add_to_delegation_balance(delegation_target, amount_to_delegate)?;

        self.add_balance_to_pool(pool_id, amount_to_delegate)?;

        self.add_delegation_to_pool_share(pool_id, delegation_target, amount_to_delegate)?;

        Ok(PoSAccountingUndo::DelegateStaking(DelegateStakingUndo {
            delegation_target,
            amount_to_delegate,
        }))
    }

    pub fn undo_delegate_staking(&mut self, undo_data: DelegateStakingUndo) -> Result<(), Error> {
        let pool_id = *self.get_delegation_data(undo_data.delegation_target)?.source_pool();

        self.undo_add_delegation_to_pool_share(
            pool_id,
            undo_data.delegation_target,
            undo_data.amount_to_delegate,
        )?;

        self.undo_add_balance_to_pool(pool_id, undo_data.amount_to_delegate)?;

        self.undo_add_to_delegation_balance(
            undo_data.delegation_target,
            undo_data.amount_to_delegate,
        )?;

        Ok(())
    }
}

impl<S: PoSAccountingStorageRead> PoSAccounting<S> {
    pub fn pool_exists(&self, pool_id: H256) -> Result<bool, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from).map(|v| v.is_some())
    }

    fn get_delegation_data(&self, delegation_target: H256) -> Result<DelegationData, Error> {
        let delegation_target = self
            .store
            .get_delegation_data(delegation_target)
            .map_err(Error::from)?
            .ok_or(Error::DelegateToNonexistingId)?;
        Ok(delegation_target)
    }

    // TODO: test that all values within the pool will be returned, especially boundary values, and off boundary aren't returned
    pub fn get_delegation_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Error::from)
    }

    pub fn get_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(Error::from)
    }

    pub fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from)
    }

    pub fn get_delegation_id_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_delegation_balance(delegation_id).map_err(Error::from)
    }

    pub fn get_delegation_id_data(
        &self,
        delegation_id: H256,
    ) -> Result<Option<DelegationData>, Error> {
        self.store.get_delegation_data(delegation_id).map_err(Error::from)
    }
}

impl<S: PoSAccountingStorageRead> PoSAccountingView for PoSAccounting<S> {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from)
    }

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error> {
        self.store.get_pool_data(pool_id).map_err(Error::from)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Error::from)
    }

    fn get_delegation_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_delegation_balance(delegation_id).map_err(Error::from)
    }

    fn get_delegation_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error> {
        self.store.get_delegation_data(delegation_id).map_err(Error::from)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(Error::from)
    }
}

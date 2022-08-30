use std::collections::BTreeMap;

use common::{
    chain::OutPoint,
    primitives::{Amount, H256},
};
use crypto::key::PublicKey;

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        helpers::{make_delegation_id, make_pool_id},
        operations::{
            CreateDelegationIdUndo, CreatePoolUndo, DecommissionPoolUndo, DelegateStakingUndo,
            PoSAccountingOperatorRead, PoSAccountingOperatorWrite, PoSAccountingUndo,
        },
        pool_data::PoolData,
    },
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
};

use super::PoSAccounting;

impl<S: PoSAccountingStorageWrite> PoSAccountingOperatorWrite for PoSAccounting<S> {
    fn create_pool(
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
        self.store.set_pool_data(pool_id, &PoolData::new(decommission_key))?;

        Ok(PoSAccountingUndo::CreatePool(CreatePoolUndo {
            input0_outpoint: input0_outpoint.clone(),
            pledge_amount,
        }))
    }

    fn undo_create_pool(&mut self, undo_data: CreatePoolUndo) -> Result<(), Error> {
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

    fn decommission_pool(&mut self, pool_id: H256) -> Result<PoSAccountingUndo, Error> {
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

    fn undo_decommission_pool(&mut self, undo_data: DecommissionPoolUndo) -> Result<(), Error> {
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

    fn create_delegation_id(
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

    fn undo_create_delegation_id(
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

    fn delegate_staking(
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

    fn undo_delegate_staking(&mut self, undo_data: DelegateStakingUndo) -> Result<(), Error> {
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

impl<S: PoSAccountingStorageRead> PoSAccountingOperatorRead for PoSAccounting<S> {
    fn pool_exists(&self, pool_id: H256) -> Result<bool, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from).map(|v| v.is_some())
    }

    // TODO: test that all values within the pool will be returned, especially boundary values, and off boundary aren't returned
    fn get_delegation_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Error::from)
    }

    fn get_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(Error::from)
    }

    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from)
    }

    fn get_delegation_id_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        self.store.get_delegation_balance(delegation_id).map_err(Error::from)
    }

    fn get_delegation_id_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error> {
        self.store.get_delegation_data(delegation_id).map_err(Error::from)
    }
}

use std::collections::BTreeMap;

use common::{chain::OutPoint, primitives::Amount};
use crypto::key::PublicKey;

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        helpers::{make_delegation_id, make_pool_id},
        operations::{
            CreateDelegationIdUndo, CreatePoolUndo, DecommissionPoolUndo, DelegateStakingUndo,
            DelegationDataUndo, PoSAccountingOperatorRead, PoSAccountingOperatorWrite,
            PoSAccountingUndo, PoolDataUndo, SpendFromShareUndo,
        },
        pool_data::PoolData,
    },
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
    DelegationId, PoolId,
};

use super::PoSAccountingDBMut;

impl<'a, S: PoSAccountingStorageWrite> PoSAccountingOperatorWrite for PoSAccountingDBMut<'a, S> {
    fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
        decommission_key: PublicKey,
    ) -> Result<(PoolId, PoSAccountingUndo), Error> {
        let pool_id = make_pool_id(input0_outpoint);

        if self.store.get_pool_balance(pool_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorPoolBalanceAlreadyExists);
        }

        if self.store.get_pool_data(pool_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorPoolDataAlreadyExists);
        }
        let pool_data = PoolData::new(decommission_key, pledge_amount);

        self.store.set_pool_balance(pool_id, pledge_amount)?;
        self.store.set_pool_data(pool_id, &pool_data)?;

        Ok((
            pool_id,
            PoSAccountingUndo::CreatePool(CreatePoolUndo {
                pool_id,
                data_undo: PoolDataUndo::Data(pool_data),
            }),
        ))
    }

    fn decommission_pool(&mut self, pool_id: PoolId) -> Result<PoSAccountingUndo, Error> {
        let pool_data = self
            .store
            .get_pool_data(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolData)?;

        self.store.del_pool_balance(pool_id)?;
        self.store.del_pool_data(pool_id)?;

        Ok(PoSAccountingUndo::DecommissionPool(DecommissionPoolUndo {
            pool_id,
            data_undo: PoolDataUndo::Data(pool_data),
        }))
    }

    fn create_delegation_id(
        &mut self,
        target_pool: PoolId,
        spend_key: PublicKey,
        input0_outpoint: &OutPoint,
    ) -> Result<(DelegationId, PoSAccountingUndo), Error> {
        if !self.pool_exists(target_pool)? {
            return Err(Error::DelegationCreationFailedPoolDoesNotExist);
        }

        let delegation_id = make_delegation_id(input0_outpoint);

        if self.store.get_delegation_data(delegation_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorDelegationCreationFailedIdAlreadyExists);
        }

        let delegation_data = DelegationData::new(target_pool, spend_key);

        self.store.set_delegation_data(delegation_id, &delegation_data)?;

        Ok((
            delegation_id,
            PoSAccountingUndo::CreateDelegationId(CreateDelegationIdUndo {
                delegation_id,
                data_undo: DelegationDataUndo::Data(Box::new(delegation_data)),
            }),
        ))
    }

    fn delegate_staking(
        &mut self,
        delegation_target: DelegationId,
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

    fn spend_share_from_delegation_id(
        &mut self,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_id = *self.get_delegation_data(delegation_id)?.source_pool();

        self.sub_delegation_from_pool_share(pool_id, delegation_id, amount)?;

        self.sub_balance_from_pool(pool_id, amount)?;

        self.sub_from_delegation_balance(delegation_id, amount)?;

        Ok(PoSAccountingUndo::SpendFromShare(SpendFromShareUndo {
            delegation_id,
            amount,
        }))
    }

    fn undo(&mut self, undo_data: PoSAccountingUndo) -> Result<(), Error> {
        match undo_data {
            PoSAccountingUndo::CreatePool(undo) => self.undo_create_pool(undo),
            PoSAccountingUndo::DecommissionPool(undo) => self.undo_decommission_pool(undo),
            PoSAccountingUndo::CreateDelegationId(undo) => self.undo_create_delegation_id(undo),
            PoSAccountingUndo::DelegateStaking(undo) => self.undo_delegate_staking(undo),
            PoSAccountingUndo::SpendFromShare(undo) => {
                self.undo_spend_share_from_delegation_id(undo)
            }
        }
    }
}

impl<'a, S: PoSAccountingStorageWrite> PoSAccountingDBMut<'a, S> {
    fn undo_create_pool(&mut self, undo: CreatePoolUndo) -> Result<(), Error> {
        let amount = self.store.get_pool_balance(undo.pool_id)?;

        let data_undo = match undo.data_undo {
            PoolDataUndo::Data(v) => v,
            PoolDataUndo::DataDelta(_) => unreachable!("incompatible PoolDataUndo supplied"),
        };

        match amount {
            Some(amount) => {
                if amount != data_undo.pledge_amount() {
                    return Err(Error::InvariantErrorPoolCreationReversalFailedAmountChanged);
                }
            }
            None => return Err(Error::InvariantErrorPoolCreationReversalFailedBalanceNotFound),
        }

        self.store
            .get_pool_data(undo.pool_id)?
            .ok_or(Error::InvariantErrorPoolCreationReversalFailedDataNotFound)?;

        self.store.del_pool_balance(undo.pool_id)?;
        self.store.del_pool_data(undo.pool_id)?;

        Ok(())
    }

    fn undo_decommission_pool(&mut self, undo: DecommissionPoolUndo) -> Result<(), Error> {
        let data_undo = match undo.data_undo {
            PoolDataUndo::Data(v) => v,
            PoolDataUndo::DataDelta(_) => unreachable!("incompatible PoolDataUndo supplied"),
        };

        if self.store.get_pool_balance(undo.pool_id)?.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists);
        }

        if self.store.get_pool_data(undo.pool_id)?.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists);
        }

        self.store.set_pool_balance(undo.pool_id, data_undo.pledge_amount())?;
        self.store.set_pool_data(undo.pool_id, &data_undo)?;

        Ok(())
    }

    fn undo_create_delegation_id(&mut self, undo: CreateDelegationIdUndo) -> Result<(), Error> {
        let data_undo = match undo.data_undo {
            DelegationDataUndo::Data(v) => v,
            DelegationDataUndo::DataDelta(_) => {
                unreachable!("incompatible DelegationDataUndo supplied")
            }
        };

        let removed_data = self
            .store
            .get_delegation_data(undo.delegation_id)?
            .ok_or(Error::InvariantErrorDelegationIdUndoFailedNotFound)?;

        if removed_data != *data_undo {
            return Err(Error::InvariantErrorDelegationIdUndoFailedDataConflict);
        }

        self.store.del_delegation_data(undo.delegation_id)?;

        Ok(())
    }

    fn undo_delegate_staking(&mut self, undo_data: DelegateStakingUndo) -> Result<(), Error> {
        let pool_id = *self.get_delegation_data(undo_data.delegation_target)?.source_pool();

        self.sub_delegation_from_pool_share(
            pool_id,
            undo_data.delegation_target,
            undo_data.amount_to_delegate,
        )?;

        self.sub_balance_from_pool(pool_id, undo_data.amount_to_delegate)?;

        self.sub_from_delegation_balance(
            undo_data.delegation_target,
            undo_data.amount_to_delegate,
        )?;

        Ok(())
    }

    fn undo_spend_share_from_delegation_id(
        &mut self,
        undo_data: SpendFromShareUndo,
    ) -> Result<(), Error> {
        let pool_id = *self.get_delegation_data(undo_data.delegation_id)?.source_pool();

        self.add_to_delegation_balance(undo_data.delegation_id, undo_data.amount)?;

        self.add_balance_to_pool(pool_id, undo_data.amount)?;

        self.add_delegation_to_pool_share(pool_id, undo_data.delegation_id, undo_data.amount)?;

        Ok(())
    }
}

impl<'a, S: PoSAccountingStorageRead> PoSAccountingOperatorRead for PoSAccountingDBMut<'a, S> {
    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from).map(|v| v.is_some())
    }

    // TODO: test that all values within the pool will be returned, especially boundary values, and off boundary aren't returned
    fn get_delegation_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Error::from)
    }

    fn get_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(Error::from)
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error> {
        self.store.get_pool_balance(pool_id).map_err(Error::from)
    }

    fn get_delegation_id_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        self.store.get_delegation_balance(delegation_id).map_err(Error::from)
    }

    fn get_delegation_id_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error> {
        self.store.get_delegation_data(delegation_id).map_err(Error::from)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error> {
        self.store.get_pool_data(pool_id).map_err(Error::from)
    }
}

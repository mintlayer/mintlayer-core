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
            SpendFromShareUndo,
        },
        pool_data::PoolData,
    },
};

use super::{
    combine::{combine_amount_delta, combine_data_with_delta},
    delta_data_collection::DataDeltaUndoOp,
    sum_maps, DataDelta, PoSAccountingDelta,
};

impl<'a> PoSAccountingOperatorWrite for PoSAccountingDelta<'a> {
    fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
        decommission_key: PublicKey,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_id = make_pool_id(input0_outpoint);

        {
            let current_amount = self.get_pool_balance(pool_id)?;
            if current_amount.is_some() {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolBalanceAlreadyExists);
            }
        }

        {
            let current_data = self.get_pool_data(pool_id)?;
            if current_data.is_some() {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolDataAlreadyExists);
            }
        }

        self.data.pool_balances.add_unsigned(pool_id, pledge_amount)?;
        self.data.pool_data.merge_delta_data_element(
            pool_id,
            DataDelta::Create(Box::new(PoolData::new(decommission_key, pledge_amount))),
        )?;

        Ok(PoSAccountingUndo::CreatePool(CreatePoolUndo {
            input0_outpoint: input0_outpoint.clone(),
            pledge_amount,
        }))
    }

    fn undo_create_pool(&mut self, undo_data: CreatePoolUndo) -> Result<(), Error> {
        let pool_id = make_pool_id(&undo_data.input0_outpoint);

        let amount = self.get_pool_balance(pool_id)?;

        match amount {
            Some(amount) => {
                if amount != undo_data.pledge_amount {
                    return Err(Error::InvariantErrorPoolCreationReversalFailedAmountChanged);
                }
            }
            None => return Err(Error::InvariantErrorPoolCreationReversalFailedBalanceNotFound),
        }

        let pool_data = self.get_pool_data(pool_id)?;
        {
            if pool_data.is_none() {
                return Err(Error::InvariantErrorPoolCreationReversalFailedDataNotFound);
            }
        }

        self.data
            .pool_data
            .undo_merge_delta_data_element(pool_id, DataDeltaUndoOp::Erase)?;

        Ok(())
    }

    fn decommission_pool(&mut self, pool_id: H256) -> Result<PoSAccountingUndo, Error> {
        let last_amount = self
            .get_pool_balance(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolBalance)?;

        let pool_data = self
            .get_pool_data(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolData)?;

        self.data.pool_data.merge_delta_data_element(pool_id, DataDelta::Delete)?;

        Ok(PoSAccountingUndo::DecommissionPool(DecommissionPoolUndo {
            pool_id,
            last_amount,
            pool_data,
        }))
    }

    fn undo_decommission_pool(&mut self, undo_data: DecommissionPoolUndo) -> Result<(), Error> {
        let current_amount = self.get_pool_balance(undo_data.pool_id)?;
        if current_amount.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists);
        }

        let current_data = self.get_pool_data(undo_data.pool_id)?;
        if current_data.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists);
        }

        self.data.pool_balances.add_unsigned(undo_data.pool_id, undo_data.last_amount)?;

        // TODO: all DataDeltaUndoOp usages are intrusive and should not be allowed,
        //       as undo should be generated from the delta operation and not be manually
        //       injected from individual data elemenets
        self.data.pool_data.undo_merge_delta_data_element(
            undo_data.pool_id,
            DataDeltaUndoOp::Write(DataDelta::Create(Box::new(undo_data.pool_data))),
        )?;

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
            let current_delegation_data = self.get_delegation_id_data(delegation_id)?;
            if current_delegation_data.is_some() {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorDelegationCreationFailedIdAlreadyExists);
            }
        }

        let delegation_data = DelegationData::new(target_pool, spend_key);

        self.data.delegation_data.merge_delta_data_element(
            delegation_id,
            DataDelta::Create(Box::new(delegation_data.clone())),
        )?;

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
            .get_delegation_id_data(delegation_id)?
            .ok_or(Error::InvariantErrorDelegationIdUndoFailedNotFound)?;

        if removed_data != undo_data.delegation_data {
            return Err(Error::InvariantErrorDelegationIdUndoFailedDataConflict);
        }

        self.data
            .delegation_data
            .undo_merge_delta_data_element(delegation_id, DataDeltaUndoOp::Erase)?;

        Ok(())
    }

    fn delegate_staking(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_id = *self
            .get_delegation_id_data(delegation_target)?
            .ok_or(Error::DelegationCreationFailedPoolDoesNotExist)?
            .source_pool();

        self.add_to_delegation_balance(delegation_target, amount_to_delegate)?;

        self.add_balance_to_pool(pool_id, amount_to_delegate)?;

        self.add_delegation_to_pool_share(pool_id, delegation_target, amount_to_delegate)?;

        Ok(PoSAccountingUndo::DelegateStaking(DelegateStakingUndo {
            delegation_target,
            amount_to_delegate,
        }))
    }

    fn undo_delegate_staking(&mut self, undo_data: DelegateStakingUndo) -> Result<(), Error> {
        let pool_id = *self
            .get_delegation_id_data(undo_data.delegation_target)?
            .ok_or(Error::InvariantErrorDelegationUndoFailedDataNotFound)?
            .source_pool();

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

    fn spend_share_from_delegation_id(
        &mut self,
        delegation_id: H256,
        amount: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_id = *self
            .get_delegation_id_data(delegation_id)?
            .ok_or(Error::InvariantErrorDelegationUndoFailedDataNotFound)?
            .source_pool();

        self.sub_delegation_from_pool_share(pool_id, delegation_id, amount)?;

        self.sub_balance_from_pool(pool_id, amount)?;

        self.sub_from_delegation_balance(delegation_id, amount)?;

        Ok(PoSAccountingUndo::SpendFromShare(SpendFromShareUndo {
            delegation_id,
            amount,
        }))
    }
}

impl<'a> PoSAccountingOperatorRead for PoSAccountingDelta<'a> {
    fn pool_exists(&self, pool_id: H256) -> Result<bool, Error> {
        Ok(self.parent.get_pool_data(pool_id)?.is_some())
    }

    fn get_delegation_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        let parent_shares = self.parent.get_pool_delegations_shares(pool_id)?.unwrap_or_default();
        let local_shares = self.get_cached_delegations_shares(pool_id).unwrap_or_default();
        if parent_shares.is_empty() && local_shares.is_empty() {
            Ok(None)
        } else {
            Ok(Some(sum_maps(parent_shares, local_shares)?))
        }
    }

    fn get_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        let parent_share = self.parent.get_pool_delegation_share(pool_id, delegation_id)?;
        let local_share = self.data.pool_delegation_shares.data().get(&(pool_id, delegation_id));
        combine_amount_delta(&parent_share, &local_share.copied())
    }

    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_pool_balance(pool_id)?;
        let local_amount = self.data.pool_balances.data().get(&pool_id);
        combine_amount_delta(&parent_amount, &local_amount.copied())
    }

    fn get_delegation_id_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_delegation_balance(delegation_id)?;
        let local_amount = self.data.delegation_balances.data().get(&delegation_id);
        combine_amount_delta(&parent_amount, &local_amount.copied())
    }

    fn get_delegation_id_data(&self, id: H256) -> Result<Option<DelegationData>, Error> {
        let parent_data = self.parent.get_delegation_data(id)?;
        let local_data = self.data.delegation_data.data().get(&id);
        combine_data_with_delta(parent_data, local_data)
    }

    fn get_pool_data(&self, id: H256) -> Result<Option<PoolData>, Error> {
        let parent_data = self.parent.get_pool_data(id)?;
        let local_data = self.data.pool_data.data().get(&id);
        combine_data_with_delta(parent_data, local_data)
    }
}

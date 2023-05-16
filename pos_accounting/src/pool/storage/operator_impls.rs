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

use common::{
    chain::{DelegationId, Destination, OutPoint, PoolId},
    primitives::Amount,
};

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        helpers::{make_delegation_id, make_pool_id},
        operations::{
            CreateDelegationIdUndo, CreatePoolUndo, DecommissionPoolUndo, DelegateStakingUndo,
            DelegationDataUndo, IncreasePledgeAmountUndo, PoSAccountingOperations,
            PoSAccountingUndo, PoolDataUndo, SpendFromShareUndo,
        },
        pool_data::PoolData,
        view::PoSAccountingView,
    },
    storage::PoSAccountingStorageWrite,
    PoSAccountingDB, StorageTag,
};

impl<S: PoSAccountingStorageWrite<T>, T: StorageTag> PoSAccountingOperations
    for PoSAccountingDB<S, T>
{
    fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pool_data: PoolData,
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

        self.store.set_pool_balance(pool_id, pool_data.pledge_amount())?;
        self.store.set_pool_data(pool_id, &pool_data)?;

        Ok((
            pool_id,
            PoSAccountingUndo::CreatePool(CreatePoolUndo {
                pool_id,
                pledge_amount: pool_data.pledge_amount(),
                data_undo: PoolDataUndo::Data(Box::new(pool_data)),
            }),
        ))
    }

    fn decommission_pool(&mut self, pool_id: PoolId) -> Result<PoSAccountingUndo, Error> {
        let pool_data = self
            .store
            .get_pool_data(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolData)?;

        let pool_balance = self
            .store
            .get_pool_balance(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolBalance)?;

        self.store.del_pool_balance(pool_id)?;
        self.store.del_pool_data(pool_id)?;

        Ok(PoSAccountingUndo::DecommissionPool(DecommissionPoolUndo {
            pool_id,
            pool_balance,
            data_undo: PoolDataUndo::Data(Box::new(pool_data)),
        }))
    }

    fn increase_pool_pledge_amount(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_data = self
            .store
            .get_pool_data(pool_id)?
            .ok_or(Error::IncreasePledgeAmountOfNonexistingPool)?;
        let new_pool_data = PoolData::new(
            pool_data.decommission_destination().clone(),
            (pool_data.pledge_amount() + amount_to_add).ok_or(Error::PledgeAmountAdditionError)?,
            pool_data.vrf_public_key().clone(),
            pool_data.margin_ratio_per_thousand(),
            pool_data.cost_per_block(),
        );
        self.store.set_pool_data(pool_id, &new_pool_data)?;

        self.add_balance_to_pool(pool_id, amount_to_add)?;

        Ok(PoSAccountingUndo::IncreasePledgeAmount(
            IncreasePledgeAmountUndo {
                pool_id,
                amount_added: amount_to_add,
                data_undo: PoolDataUndo::Data(Box::new(pool_data)),
            },
        ))
    }

    fn create_delegation_id(
        &mut self,
        target_pool: PoolId,
        spend_key: Destination,
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
        let pool_id = *self
            .get_delegation_data(delegation_target)?
            .ok_or(Error::DelegateToNonexistingId)?
            .source_pool();

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
        let pool_id = *self
            .get_delegation_data(delegation_id)?
            .ok_or(Error::InvariantErrorDelegationUndoFailedDataNotFound)?
            .source_pool();

        self.sub_delegation_from_pool_share(pool_id, delegation_id, amount)?;

        // it's possible that the pool was decommissioned
        if self.pool_exists(pool_id)? {
            self.sub_balance_from_pool(pool_id, amount)?;
        }

        self.sub_from_delegation_balance(delegation_id, amount)?;

        // FIXME: delete delegation id if balance is 0 and the pool has been already decommissioned

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
            PoSAccountingUndo::IncreasePledgeAmount(undo) => self.undo_increase_pledge_amount(undo),
        }
    }
}

impl<S: PoSAccountingStorageWrite<T>, T: StorageTag> PoSAccountingDB<S, T> {
    fn undo_create_pool(&mut self, undo: CreatePoolUndo) -> Result<(), Error> {
        match undo.data_undo {
            PoolDataUndo::Data(v) => v,
            PoolDataUndo::DataDelta(_) => panic!("incompatible PoolDataUndo supplied"),
        };

        match self.store.get_pool_balance(undo.pool_id)? {
            Some(pool_balance) => {
                if pool_balance != undo.pledge_amount {
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
            PoolDataUndo::DataDelta(_) => panic!("incompatible PoolDataUndo supplied"),
        };

        if self.store.get_pool_balance(undo.pool_id)?.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists);
        }

        if self.store.get_pool_data(undo.pool_id)?.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists);
        }

        self.store.set_pool_balance(undo.pool_id, undo.pool_balance)?;
        self.store.set_pool_data(undo.pool_id, &data_undo)?;

        Ok(())
    }

    fn undo_create_delegation_id(&mut self, undo: CreateDelegationIdUndo) -> Result<(), Error> {
        let data_undo = match undo.data_undo {
            DelegationDataUndo::Data(v) => v,
            DelegationDataUndo::DataDelta(_) => {
                panic!("incompatible DelegationDataUndo supplied")
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
        let pool_id = *self
            .get_delegation_data(undo_data.delegation_target)?
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

    fn undo_spend_share_from_delegation_id(
        &mut self,
        undo_data: SpendFromShareUndo,
    ) -> Result<(), Error> {
        let pool_id = *self
            .get_delegation_data(undo_data.delegation_id)?
            .ok_or(Error::DelegationCreationFailedPoolDoesNotExist)?
            .source_pool();

        self.add_to_delegation_balance(undo_data.delegation_id, undo_data.amount)?;

        // it's possible that the pool was decommissioned
        if self.pool_exists(pool_id)? {
            self.add_balance_to_pool(pool_id, undo_data.amount)?;
        }

        self.add_delegation_to_pool_share(pool_id, undo_data.delegation_id, undo_data.amount)?;

        Ok(())
    }

    fn undo_increase_pledge_amount(&mut self, undo: IncreasePledgeAmountUndo) -> Result<(), Error> {
        let data_undo = match undo.data_undo {
            PoolDataUndo::Data(v) => v,
            PoolDataUndo::DataDelta(_) => panic!("incompatible PoolDataUndo supplied"),
        };

        if self.store.get_pool_balance(undo.pool_id)?.is_none() {
            return Err(Error::InvariantErrorIncreasePledgeUndoFailedPoolBalanceNotFound);
        }

        self.sub_balance_from_pool(undo.pool_id, undo.amount_added)?;

        self.store.set_pool_data(undo.pool_id, &data_undo)?;

        Ok(())
    }
}

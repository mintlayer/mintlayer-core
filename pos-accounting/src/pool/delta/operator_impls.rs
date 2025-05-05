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

use accounting::DataDelta;
use common::{
    chain::{DelegationId, Destination, PoolId},
    primitives::Amount,
};
use utils::ensure;

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        operations::{
            CreateDelegationIdUndo, CreatePoolUndo, DecommissionPoolUndo, DelegateStakingUndo,
            DeleteDelegationIdUndo, IncreaseStakerRewardsUndo, PoSAccountingOperations,
            PoSAccountingUndo, SpendFromShareUndo,
        },
        pool_data::PoolData,
        view::PoSAccountingView,
    },
};

use super::PoSAccountingDelta;

impl<P: PoSAccountingView> PoSAccountingOperations<PoSAccountingUndo> for PoSAccountingDelta<P> {
    fn create_pool(
        &mut self,
        pool_id: PoolId,
        pool_data: PoolData,
    ) -> Result<PoSAccountingUndo, Error> {
        let pledge_amount = pool_data.pledge_amount();

        if self.get_pool_data(pool_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorPoolDataAlreadyExists);
        }

        if self.get_pool_balance(pool_id).map_err(|_| Error::ViewFail)? > Amount::ZERO {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorPoolBalanceAlreadyExists);
        }

        self.data.pool_balances.add_unsigned(pool_id, pledge_amount)?;

        let data_undo = self
            .data
            .pool_data
            .merge_delta_data_element(pool_id, DataDelta::new(None, Some(pool_data)))?;

        Ok(PoSAccountingUndo::CreatePool(CreatePoolUndo {
            pool_id,
            pledge_amount,
            data_undo,
        }))
    }

    fn decommission_pool(&mut self, pool_id: PoolId) -> Result<PoSAccountingUndo, Error> {
        let last_data = self
            .get_pool_data(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolData)?;

        let last_amount = self.get_pool_balance(pool_id)?;

        self.data.pool_balances.sub_unsigned(pool_id, last_amount)?;
        let data_undo = self
            .data
            .pool_data
            .merge_delta_data_element(pool_id, DataDelta::new(Some(last_data), None))?;

        Ok(PoSAccountingUndo::DecommissionPool(DecommissionPoolUndo {
            pool_id,
            pool_balance: last_amount,
            data_undo,
        }))
    }

    fn increase_staker_rewards(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_data = self
            .get_pool_data(pool_id)?
            .ok_or(Error::IncreaseStakerRewardsOfNonexistingPool)?;

        self.add_balance_to_pool(pool_id, amount_to_add)?;

        let new_pool_data = pool_data.clone().increase_staker_rewards(amount_to_add)?;
        let data_undo = self.data.pool_data.merge_delta_data_element(
            pool_id,
            DataDelta::new(Some(pool_data), Some(new_pool_data)),
        )?;

        Ok(PoSAccountingUndo::IncreaseStakerRewards(
            IncreaseStakerRewardsUndo {
                pool_id,
                amount_added: amount_to_add,
                data_undo,
            },
        ))
    }

    fn create_delegation_id(
        &mut self,
        target_pool: PoolId,
        delegation_id: DelegationId,
        spend_key: Destination,
    ) -> Result<PoSAccountingUndo, Error> {
        if !self.pool_exists(target_pool)? {
            return Err(Error::DelegationCreationFailedPoolDoesNotExist);
        }

        if self.get_delegation_data(delegation_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorDelegationCreationFailedIdAlreadyExists);
        }

        let delegation_data = DelegationData::new(target_pool, spend_key);

        let data_undo = self
            .data
            .delegation_data
            .merge_delta_data_element(delegation_id, DataDelta::new(None, Some(delegation_data)))?;

        Ok(PoSAccountingUndo::CreateDelegationId(
            CreateDelegationIdUndo {
                delegation_id,
                data_undo,
            },
        ))
    }

    fn delete_delegation_id(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<PoSAccountingUndo, Error> {
        let delegation_data = self
            .get_delegation_data(delegation_id)?
            .ok_or(Error::DelegationDeletionFailedIdDoesNotExist)?;

        if self.get_delegation_balance(delegation_id)? > Amount::ZERO {
            return Err(Error::DelegationDeletionFailedBalanceNonZero);
        }

        if self.get_pool_delegation_share(*delegation_data.source_pool(), delegation_id)?
            > Amount::ZERO
        {
            return Err(Error::DelegationDeletionFailedPoolsShareNonZero);
        }

        if self.pool_exists(*delegation_data.source_pool())? {
            return Err(Error::DelegationDeletionFailedPoolStillExists);
        }

        let data_undo = self
            .data
            .delegation_data
            .merge_delta_data_element(delegation_id, DataDelta::new(Some(delegation_data), None))?;

        Ok(PoSAccountingUndo::DeleteDelegationId(
            DeleteDelegationIdUndo {
                delegation_id,
                data_undo,
            },
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
            .ok_or(Error::SpendingShareOfNonexistingDelegation(delegation_id))?
            .source_pool();

        self.sub_delegation_from_pool_share(pool_id, delegation_id, amount)?;

        // it's possible that the pool was decommissioned
        if self.pool_exists(pool_id)? {
            self.sub_balance_from_pool(pool_id, amount)?;
        }

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
            PoSAccountingUndo::DeleteDelegationId(undo) => self.undo_delete_delegation_id(undo),
            PoSAccountingUndo::DelegateStaking(undo) => self.undo_delegate_staking(undo),
            PoSAccountingUndo::SpendFromShare(undo) => {
                self.undo_spend_share_from_delegation_id(undo)
            }
            PoSAccountingUndo::IncreaseStakerRewards(undo) => {
                self.undo_increase_staker_balance(undo)
            }
        }
    }
}

impl<P: PoSAccountingView> PoSAccountingDelta<P> {
    fn undo_create_pool(&mut self, undo: CreatePoolUndo) -> Result<(), Error> {
        ensure!(
            self.get_pool_balance(undo.pool_id)? == undo.pledge_amount,
            Error::InvariantErrorPoolCreationReversalFailedAmountChanged
        );

        self.data.pool_balances.sub_unsigned(undo.pool_id, undo.pledge_amount)?;

        self.get_pool_data(undo.pool_id)?
            .ok_or(Error::InvariantErrorPoolCreationReversalFailedDataNotFound)?;

        self.data
            .pool_data
            .undo_merge_delta_data_element(undo.pool_id, undo.data_undo)?;

        Ok(())
    }

    fn undo_decommission_pool(&mut self, undo: DecommissionPoolUndo) -> Result<(), Error> {
        if self.get_pool_data(undo.pool_id)?.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists);
        }

        if self.get_pool_balance(undo.pool_id)? > Amount::ZERO {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists);
        }

        self.data.pool_balances.add_unsigned(undo.pool_id, undo.pool_balance)?;
        self.data
            .pool_data
            .undo_merge_delta_data_element(undo.pool_id, undo.data_undo)?;

        Ok(())
    }

    fn undo_create_delegation_id(&mut self, undo: CreateDelegationIdUndo) -> Result<(), Error> {
        self.get_delegation_data(undo.delegation_id)?
            .ok_or(Error::InvariantErrorDelegationIdUndoFailedNotFound)?;

        self.data
            .delegation_data
            .undo_merge_delta_data_element(undo.delegation_id, undo.data_undo)?;

        Ok(())
    }

    fn undo_delete_delegation_id(&mut self, undo: DeleteDelegationIdUndo) -> Result<(), Error> {
        if self.get_delegation_balance(undo.delegation_id)? > Amount::ZERO {
            return Err(Error::DelegationDeletionFailedBalanceNonZero);
        }

        self.data
            .delegation_data
            .undo_merge_delta_data_element(undo.delegation_id, undo.data_undo)?;

        Ok(())
    }

    fn undo_delegate_staking(&mut self, undo_data: DelegateStakingUndo) -> Result<(), Error> {
        let pool_id = *self
            .get_delegation_data(undo_data.delegation_target)?
            .ok_or(Error::InvariantErrorDelegationUndoFailedDataNotFound(
                undo_data.delegation_target,
            ))?
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

    fn undo_increase_staker_balance(
        &mut self,
        undo: IncreaseStakerRewardsUndo,
    ) -> Result<(), Error> {
        self.data
            .pool_data
            .undo_merge_delta_data_element(undo.pool_id, undo.data_undo)?;
        self.sub_balance_from_pool(undo.pool_id, undo.amount_added)?;

        Ok(())
    }
}

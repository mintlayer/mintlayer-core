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
use common::{chain::OutPoint, primitives::Amount};
use crypto::key::PublicKey;

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        helpers::{make_delegation_id, make_pool_id},
        operations::{
            CreateDelegationIdUndo, CreatePoolUndo, DecommissionPoolUndo, DelegateStakingUndo,
            DelegationDataUndo, PoSAccountingOperations, PoSAccountingUndo, PoolDataUndo,
            SpendFromShareUndo,
        },
        pool_data::PoolData,
        view::PoSAccountingView,
    },
    DelegationId, PoolId,
};

use super::PoSAccountingDelta;

impl<'a, P: PoSAccountingView> PoSAccountingOperations for PoSAccountingDelta<'a, P> {
    fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
        decommission_key: PublicKey,
    ) -> Result<(PoolId, PoSAccountingUndo), Error> {
        let pool_id = make_pool_id(input0_outpoint);

        if self.get_pool_balance(pool_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorPoolBalanceAlreadyExists);
        }

        if self.get_pool_data(pool_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorPoolDataAlreadyExists);
        }

        self.data.pool_balances.add_unsigned(pool_id, pledge_amount)?;
        let undo_data = self
            .data
            .pool_data
            .merge_delta_data_element(
                pool_id,
                DataDelta::new(None, Some(PoolData::new(decommission_key, pledge_amount))),
            )?
            .ok_or(Error::FailedToCreateDeltaUndo)?;

        Ok((
            pool_id,
            PoSAccountingUndo::CreatePool(CreatePoolUndo {
                pool_id,
                data_undo: PoolDataUndo::DataDelta(Box::new((pledge_amount, undo_data))),
            }),
        ))
    }

    fn decommission_pool(&mut self, pool_id: PoolId) -> Result<PoSAccountingUndo, Error> {
        let last_amount = self
            .get_pool_balance(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolBalance)?;

        let last_data = self
            .get_pool_data(pool_id)?
            .ok_or(Error::AttemptedDecommissionNonexistingPoolData)?;

        self.data.pool_balances.sub_unsigned(pool_id, last_amount)?;
        let data_undo = self
            .data
            .pool_data
            .merge_delta_data_element(pool_id, DataDelta::new(Some(last_data), None))?
            .ok_or(Error::FailedToCreateDeltaUndo)?;

        Ok(PoSAccountingUndo::DecommissionPool(DecommissionPoolUndo {
            pool_id,
            data_undo: PoolDataUndo::DataDelta(Box::new((last_amount, data_undo))),
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

        if self.get_delegation_data(delegation_id)?.is_some() {
            // This should never happen since it's based on an unspent input
            return Err(Error::InvariantErrorDelegationCreationFailedIdAlreadyExists);
        }

        let delegation_data = DelegationData::new(target_pool, spend_key);

        let data_undo = self
            .data
            .delegation_data
            .merge_delta_data_element(delegation_id, DataDelta::new(None, Some(delegation_data)))?
            .ok_or(Error::FailedToCreateDeltaUndo)?;

        Ok((
            delegation_id,
            PoSAccountingUndo::CreateDelegationId(CreateDelegationIdUndo {
                delegation_id,
                data_undo: DelegationDataUndo::DataDelta(Box::new(data_undo)),
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

impl<'a, P: PoSAccountingView> PoSAccountingDelta<'a, P> {
    fn undo_create_pool(&mut self, undo: CreatePoolUndo) -> Result<(), Error> {
        let (pledge_amount, undo_data) = match undo.data_undo {
            PoolDataUndo::DataDelta(v) => *v,
            PoolDataUndo::Data(_) => unreachable!("incompatible PoolDataUndo supplied"),
        };
        let amount = self.get_pool_balance(undo.pool_id)?;

        match amount {
            Some(amount) => {
                if amount != pledge_amount {
                    return Err(Error::InvariantErrorPoolCreationReversalFailedAmountChanged);
                }
            }
            None => return Err(Error::InvariantErrorPoolCreationReversalFailedBalanceNotFound),
        }

        self.data.pool_balances.sub_unsigned(undo.pool_id, pledge_amount)?;

        self.get_pool_data(undo.pool_id)?
            .ok_or(Error::InvariantErrorPoolCreationReversalFailedDataNotFound)?;

        self.data.pool_data.undo_merge_delta_data_element(undo.pool_id, undo_data)?;

        Ok(())
    }

    fn undo_decommission_pool(&mut self, undo: DecommissionPoolUndo) -> Result<(), Error> {
        let (last_amount, undo_data) = match undo.data_undo {
            PoolDataUndo::DataDelta(v) => *v,
            PoolDataUndo::Data(_) => unreachable!("incompatible PoolDataUndo supplied"),
        };

        if self.get_pool_balance(undo.pool_id)?.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists);
        }

        if self.get_pool_data(undo.pool_id)?.is_some() {
            return Err(Error::InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists);
        }

        self.data.pool_balances.add_unsigned(undo.pool_id, last_amount)?;
        self.data.pool_data.undo_merge_delta_data_element(undo.pool_id, undo_data)?;

        Ok(())
    }

    fn undo_create_delegation_id(&mut self, undo: CreateDelegationIdUndo) -> Result<(), Error> {
        let undo_data = match undo.data_undo {
            DelegationDataUndo::DataDelta(v) => v,
            DelegationDataUndo::Data(_) => unreachable!("incompatible DelegationDataUndo supplied"),
        };

        self.get_delegation_data(undo.delegation_id)?
            .ok_or(Error::InvariantErrorDelegationIdUndoFailedNotFound)?;

        self.data
            .delegation_data
            .undo_merge_delta_data_element(undo.delegation_id, *undo_data)?;

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

        self.add_balance_to_pool(pool_id, undo_data.amount)?;

        self.add_delegation_to_pool_share(pool_id, undo_data.delegation_id, undo_data.amount)?;

        Ok(())
    }
}

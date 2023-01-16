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

use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use common::primitives::Amount;

use crate::{
    pool::{delegation::DelegationData, pool_data::PoolData},
    DelegationId, PoolId,
};

use chainstate_types::storage_result;

pub trait PoSAccountingStorageRead {
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, storage_result::Error>;

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, storage_result::Error>;

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error>;

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, storage_result::Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, storage_result::Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error>;
}

pub trait PoSAccountingStorageWrite: PoSAccountingStorageRead {
    fn set_pool_balance(
        &mut self,
        pool_id: PoolId,
        amount: Amount,
    ) -> Result<(), storage_result::Error>;

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error>;

    fn set_pool_data(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolData,
    ) -> Result<(), storage_result::Error>;

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error>;

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error>;

    fn del_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
    ) -> Result<(), storage_result::Error>;

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> Result<(), storage_result::Error>;

    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error>;

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error>;

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error>;
}

impl<T> PoSAccountingStorageRead for T
where
    T: Deref,
    <T as Deref>::Target: PoSAccountingStorageRead,
{
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, storage_result::Error> {
        self.deref().get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, storage_result::Error> {
        self.deref().get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error> {
        self.deref().get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, storage_result::Error> {
        self.deref().get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, storage_result::Error> {
        self.deref().get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error> {
        self.deref().get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<T> PoSAccountingStorageWrite for T
where
    T: DerefMut,
    <T as Deref>::Target: PoSAccountingStorageWrite,
{
    fn set_pool_balance(
        &mut self,
        pool_id: PoolId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().set_pool_balance(pool_id, amount)
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error> {
        self.deref_mut().del_pool_balance(pool_id)
    }

    fn set_pool_data(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolData,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().set_pool_data(pool_id, pool_data)
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error> {
        self.deref_mut().del_pool_data(pool_id)
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().set_delegation_balance(delegation_target, amount)
    }

    fn del_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().del_delegation_balance(delegation_target)
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().set_delegation_data(delegation_id, delegation_data)
    }

    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().del_delegation_data(delegation_id)
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().set_pool_delegation_share(pool_id, delegation_id, amount)
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.deref_mut().del_pool_delegation_share(pool_id, delegation_id)
    }
}

#[cfg(test)]
pub(crate) mod in_memory;

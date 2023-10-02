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

use common::{
    chain::{DelegationId, PoolId},
    primitives::Amount,
};

use crate::pool::{delegation::DelegationData, pool_data::PoolData};

pub mod in_memory;

pub trait StorageTag {}

pub struct DefaultStorageTag;
impl StorageTag for DefaultStorageTag {}

pub trait PoSAccountingStorageRead<Tag: StorageTag = DefaultStorageTag> {
    type Error: std::error::Error;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error>;

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error>;

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error>;

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error>;
}

pub trait PoSAccountingStorageWrite<Tag: StorageTag = DefaultStorageTag>:
    PoSAccountingStorageRead<Tag>
{
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> Result<(), Self::Error>;

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), Self::Error>;

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> Result<(), Self::Error>;

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), Self::Error>;

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), Self::Error>;

    fn del_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
    ) -> Result<(), Self::Error>;

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> Result<(), Self::Error>;

    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> Result<(), Self::Error>;

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), Self::Error>;

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), Self::Error>;
}

impl<V, T> PoSAccountingStorageRead<T> for V
where
    V: Deref,
    T: StorageTag,
    <V as Deref>::Target: PoSAccountingStorageRead<T>,
{
    type Error = <V::Target as PoSAccountingStorageRead<T>>::Error;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        self.deref().get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        self.deref().get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.deref().get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        self.deref().get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        self.deref().get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.deref().get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<V, T> PoSAccountingStorageWrite<T> for V
where
    V: DerefMut,
    T: StorageTag,
    <V as Deref>::Target: PoSAccountingStorageWrite<T>,
{
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> Result<(), Self::Error> {
        self.deref_mut().set_pool_balance(pool_id, amount)
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), Self::Error> {
        self.deref_mut().del_pool_balance(pool_id)
    }

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> Result<(), Self::Error> {
        self.deref_mut().set_pool_data(pool_id, pool_data)
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), Self::Error> {
        self.deref_mut().del_pool_data(pool_id)
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), Self::Error> {
        self.deref_mut().set_delegation_balance(delegation_target, amount)
    }

    fn del_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
    ) -> Result<(), Self::Error> {
        self.deref_mut().del_delegation_balance(delegation_target)
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> Result<(), Self::Error> {
        self.deref_mut().set_delegation_data(delegation_id, delegation_data)
    }

    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> Result<(), Self::Error> {
        self.deref_mut().del_delegation_data(delegation_id)
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), Self::Error> {
        self.deref_mut().set_pool_delegation_share(pool_id, delegation_id, amount)
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), Self::Error> {
        self.deref_mut().del_pool_delegation_share(pool_id, delegation_id)
    }
}

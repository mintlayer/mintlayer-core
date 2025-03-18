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

use std::{collections::BTreeMap, ops::Deref};

use common::{
    chain::{DelegationId, PoolData, PoolId},
    primitives::Amount,
};

use crate::DeltaMergeUndo;

use super::{delegation::DelegationData, delta::data::PoSAccountingDeltaData};

pub trait PoSAccountingView {
    type Error: std::error::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Self::Error>;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Amount, Self::Error>;

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error>;

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Amount, Self::Error>;

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Amount, Self::Error>;
}

pub trait FlushablePoSAccountingView {
    type Error: std::error::Error;

    fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Self::Error>;
}

impl<T> PoSAccountingView for T
where
    T: Deref,
    <T as Deref>::Target: PoSAccountingView,
{
    type Error = <T::Target as PoSAccountingView>::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Self::Error> {
        self.deref().pool_exists(pool_id)
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Amount, Self::Error> {
        self.deref().get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        self.deref().get_pool_data(pool_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        self.deref().get_pool_delegations_shares(pool_id)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Amount, Self::Error> {
        self.deref().get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        self.deref().get_delegation_data(delegation_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Amount, Self::Error> {
        self.deref().get_pool_delegation_share(pool_id, delegation_id)
    }
}

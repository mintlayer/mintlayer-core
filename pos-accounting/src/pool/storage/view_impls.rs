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

use std::collections::BTreeMap;

use common::{
    chain::{DelegationId, PoolId},
    primitives::Amount,
};

use crate::{
    pool::{
        delegation::DelegationData,
        delta::data::PoSAccountingDeltaData,
        pool_data::PoolData,
        view::{FlushablePoSAccountingView, PoSAccountingView},
    },
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
    DeltaMergeUndo, PoSAccountingDB, StorageTag,
};

impl<S: PoSAccountingStorageRead<T>, T: StorageTag> PoSAccountingView for PoSAccountingDB<S, T> {
    type Error = S::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Self::Error> {
        PoSAccountingView::get_pool_data(self, pool_id).map(|v| v.is_some())
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Amount, Self::Error> {
        self.store
            .get_pool_balance(pool_id)
            .map(|v| v.unwrap_or(Amount::ZERO))
            .map_err(Self::Error::from)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        self.store.get_pool_data(pool_id).map_err(Self::Error::from)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Self::Error::from)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Amount, Self::Error> {
        self.store
            .get_delegation_balance(delegation_id)
            .map(|v| v.unwrap_or(Amount::ZERO))
            .map_err(Self::Error::from)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        self.store.get_delegation_data(delegation_id).map_err(Self::Error::from)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Amount, Self::Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map(|v| v.unwrap_or(Amount::ZERO))
            .map_err(Self::Error::from)
    }
}

impl<S: PoSAccountingStorageWrite<T>, T: StorageTag> FlushablePoSAccountingView
    for PoSAccountingDB<S, T>
{
    type Error = crate::Error;

    fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Self::Error> {
        self.merge_with_delta(data)
    }
}

impl<S: PoSAccountingStorageRead<T>, T: StorageTag> PoSAccountingStorageRead
    for PoSAccountingDB<S, T>
{
    type Error = S::Error;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        self.store.get_pool_balance(pool_id).map_err(Self::Error::from)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        self.store.get_pool_data(pool_id).map_err(Self::Error::from)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        self.store.get_pool_delegations_shares(pool_id).map_err(Self::Error::from)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.store.get_delegation_balance(delegation_id).map_err(Self::Error::from)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        self.store.get_delegation_data(delegation_id).map_err(Self::Error::from)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.store
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(Self::Error::from)
    }
}

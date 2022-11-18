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

use common::primitives::Amount;

use crate::{error::Error, DelegationId, PoolId};

use super::{delegation::DelegationData, delta::data::PoSAccountingDeltaData, pool_data::PoolData};

pub trait PoSAccountingView {
    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Error>;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error>;

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error>;

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error>;

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error>;

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error>;

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error>;
}

pub trait FlushablePoSAccountingView {
    fn batch_write_delta(&mut self, data: PoSAccountingDeltaData) -> Result<(), Error>;
}

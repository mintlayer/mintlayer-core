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

use accounting::{DeltaAmountCollection, DeltaDataCollection};

use crate::{
    pool::{delegation::DelegationData, pool_data::PoolData},
    DelegationId, PoolId,
};

use serialization::{Decode, Encode};

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct PoSAccountingDeltaData {
    pub pool_data: DeltaDataCollection<PoolId, PoolData>,
    pub pool_balances: DeltaAmountCollection<PoolId>,
    pub pool_delegation_shares: DeltaAmountCollection<(PoolId, DelegationId)>,
    pub delegation_balances: DeltaAmountCollection<DelegationId>,
    pub delegation_data: DeltaDataCollection<DelegationId, DelegationData>,
}

impl PoSAccountingDeltaData {
    pub fn new() -> Self {
        Self {
            pool_data: DeltaDataCollection::new(),
            pool_balances: DeltaAmountCollection::new(),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        }
    }
}

impl Default for PoSAccountingDeltaData {
    fn default() -> Self {
        Self::new()
    }
}

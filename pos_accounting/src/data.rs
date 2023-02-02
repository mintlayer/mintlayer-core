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
use serialization::{Decode, Encode};

use crate::{DelegationData, DelegationId, PoolData, PoolId};

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct PoSAccountingData {
    /// A collection of all the pools and their data.
    pub pool_data: BTreeMap<PoolId, PoolData>,
    /// A collection of all the pools and their balances.
    pub pool_balances: BTreeMap<PoolId, Amount>,
    /// A collection of all the pools and their delegation shares.
    pub pool_delegation_shares: BTreeMap<(PoolId, DelegationId), Amount>,
    /// A collection of all the delegations and their balances.
    pub delegation_balances: BTreeMap<DelegationId, Amount>,
    /// A collection of all the delegations and their data.
    pub delegation_data: BTreeMap<DelegationId, DelegationData>,
}

impl PoSAccountingData {
    pub fn new() -> Self {
        Self {
            pool_data: BTreeMap::new(),
            pool_balances: BTreeMap::new(),
            pool_delegation_shares: BTreeMap::new(),
            delegation_balances: BTreeMap::new(),
            delegation_data: BTreeMap::new(),
        }
    }

    // TODO: avoid manual implementation (mintlayer/mintlayer-core#669)
    pub fn is_empty(&self) -> bool {
        self.pool_data.is_empty()
            && self.pool_balances.is_empty()
            && self.pool_delegation_shares.is_empty()
            && self.delegation_balances.is_empty()
            && self.delegation_data.is_empty()
    }
}

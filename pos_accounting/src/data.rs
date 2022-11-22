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
    pub pool_data: BTreeMap<PoolId, PoolData>,
    pub pool_balances: BTreeMap<PoolId, Amount>,
    pub pool_delegation_shares: BTreeMap<(PoolId, DelegationId), Amount>,
    pub delegation_balances: BTreeMap<DelegationId, Amount>,
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
}

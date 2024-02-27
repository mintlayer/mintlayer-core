// Copyright (c) 2024 RBB S.r.l
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

use crate::random_tx_maker::StakingPoolsObserver;
use common::chain::PoolId;
use crypto::{key::PrivateKey, vrf::VRFPrivateKey};

pub struct StakingPools {
    staking_pools: BTreeMap<PoolId, (PrivateKey, VRFPrivateKey)>,
}

impl StakingPools {
    pub fn new() -> Self {
        Self {
            staking_pools: BTreeMap::new(),
        }
    }

    pub fn from_data(staking_pools: BTreeMap<PoolId, (PrivateKey, VRFPrivateKey)>) -> Self {
        Self { staking_pools }
    }

    pub fn staking_pools(&self) -> &BTreeMap<PoolId, (PrivateKey, VRFPrivateKey)> {
        &self.staking_pools
    }
}

impl StakingPoolsObserver for StakingPools {
    fn on_pool_created(&mut self, pool_id: PoolId, staker_key: PrivateKey, vrf_sk: VRFPrivateKey) {
        self.staking_pools.insert(pool_id, (staker_key, vrf_sk));
    }

    fn on_pool_decommissioned(&mut self, pool_id: PoolId) {
        self.staking_pools.remove(&pool_id);
    }
}

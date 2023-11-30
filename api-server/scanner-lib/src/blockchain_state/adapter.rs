// Copyright (c) 2023 RBB S.r.l
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

use api_server_common::storage::storage_api::Delegation;
use common::chain::{DelegationId, PoolId};
use common::primitives::Amount;
use pos_accounting::PoolData;
use std::collections::BTreeMap;
use tx_verifier::transaction_verifier::{DelegationSharesOperations, DelegationSharesView};

/// Helper struct used for `distribute_pos_reward`
pub struct PoSAdapter {
    pools: BTreeMap<PoolId, PoolData>,
    delegations: BTreeMap<DelegationId, Delegation>,

    delegation_rewards: Vec<(DelegationId, Amount)>,
}

impl PoSAdapter {
    pub fn new(
        pool_id: PoolId,
        pool_data: PoolData,
        delegations: BTreeMap<DelegationId, Delegation>,
    ) -> Self {
        Self {
            pools: BTreeMap::from_iter([(pool_id, pool_data)]),
            delegations,
            delegation_rewards: vec![],
        }
    }

    pub fn rewards_per_delegation(&self) -> Vec<(DelegationId, Amount, Delegation)> {
        self.delegation_rewards
            .iter()
            .copied()
            .map(|(delegation_id, reward)| {
                let data = self.delegations.get(&delegation_id).expect("must exist");
                let updated_delegation = data.add_pledge(reward);
                (delegation_id, reward, updated_delegation)
            })
            .collect()
    }
}

impl DelegationSharesView for PoSAdapter {
    type Error = pos_accounting::Error;

    fn find_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        Ok(self.pools.get(&pool_id).cloned())
    }

    fn get_pool_delegations_shares(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        let delegations =
            self.delegations.iter().map(|(key, data)| (*key, *data.balance())).collect();
        Ok(Some(delegations))
    }
}

impl DelegationSharesOperations<()> for PoSAdapter {
    fn add_reward_to_delegate(
        &mut self,
        delegation_target: DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<(), pos_accounting::Error> {
        self.delegation_rewards.push((delegation_target, amount_to_delegate));
        Ok(())
    }

    fn add_reward_to_pool_pledge(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<(), pos_accounting::Error> {
        if let Some(pool_data) = self.pools.get_mut(&pool_id) {
            *pool_data = PoolData::new(
                pool_data.decommission_destination().clone(),
                (pool_data.pledge_amount() + amount_to_add).expect("no overflow"),
                pool_data.vrf_public_key().clone(),
                pool_data.margin_ratio_per_thousand(),
                pool_data.cost_per_block(),
            );
        }
        Ok(())
    }
}

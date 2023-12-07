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
use common::chain::{DelegationId, Destination, PoolId, UtxoOutPoint};
use common::primitives::Amount;
use pos_accounting::{PoSAccountingOperations, PoSAccountingView, PoolData};
use std::collections::BTreeMap;

/// Helper struct used for distribute_pos_reward
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
                let updated_delegation = data.stake(reward);
                (delegation_id, reward, updated_delegation)
            })
            .collect()
    }
}

impl PoSAccountingView for PoSAdapter {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Self::Error> {
        Ok(self.pools.contains_key(&pool_id))
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        Ok(self.pools.get(&pool_id).cloned())
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        Ok(self.pools.get(&pool_id).map(|data| data.pledge_amount()))
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<pos_accounting::DelegationData>, Self::Error> {
        let data = self.delegations.get(&delegation_id).map(|data| {
            pos_accounting::DelegationData::new(data.pool_id(), data.spend_destination().clone())
        });
        Ok(data)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        let data = self.delegations.get(&delegation_id).map(|data| *data.balance());
        Ok(data)
    }

    fn get_pool_delegation_share(
        &self,
        _pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        let data = self.delegations.get(&delegation_id).map(|data| *data.balance());
        Ok(data)
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

impl PoSAccountingOperations<()> for PoSAdapter {
    fn undo(&mut self, _undo_data: ()) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }

    fn create_pool(
        &mut self,
        _pool_id: PoolId,
        _pool_data: PoolData,
    ) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }

    fn delegate_staking(
        &mut self,
        delegation_target: DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<(), pos_accounting::Error> {
        self.delegation_rewards.push((delegation_target, amount_to_delegate));
        Ok(())
    }

    fn decommission_pool(&mut self, _pool_id: PoolId) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }

    fn create_delegation_id(
        &mut self,
        _target_pool: PoolId,
        _spend_key: Destination,
        _input0_outpoint: &UtxoOutPoint,
    ) -> Result<(DelegationId, ()), pos_accounting::Error> {
        unimplemented!()
    }

    fn delete_delegation_id(
        &mut self,
        _delegation_id: DelegationId,
    ) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }

    fn increase_pool_pledge_amount(
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

    fn spend_share_from_delegation_id(
        &mut self,
        _delegation_id: DelegationId,
        _amount: Amount,
    ) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }
}

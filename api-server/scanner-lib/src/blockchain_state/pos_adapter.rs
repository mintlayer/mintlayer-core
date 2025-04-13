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
use common::chain::{DelegationId, Destination, PoolId};
use common::primitives::Amount;
use pos_accounting::{
    DelegationData, FlushablePoSAccountingView, InMemoryPoSAccounting, PoSAccountingDB,
    PoSAccountingDelta, PoSAccountingOperations, PoSAccountingView, PoolData,
};
use std::collections::BTreeMap;

/// Helper struct used for distribute_pos_reward
pub struct PoSAdapter {
    storage: InMemoryPoSAccounting,

    delegation_rewards: Vec<(DelegationId, Amount)>,
    pool_rewards: BTreeMap<PoolId, Amount>,
}

impl PoSAdapter {
    pub fn new(
        pool_id: PoolId,
        pool_data: PoolData,
        delegations: &BTreeMap<DelegationId, Delegation>,
    ) -> Self {
        let pool_balances = (pool_data.staker_balance().expect("cannot fail")
            + delegations
                .iter()
                .map(|(_, d)| *d.balance())
                .sum::<Option<Amount>>()
                .expect("cannot fail"))
        .expect("cannot fail");

        let mut pool_delegation_shares = BTreeMap::<(PoolId, DelegationId), Amount>::new();
        let mut delegation_balances = BTreeMap::<DelegationId, Amount>::new();
        let mut delegation_data = BTreeMap::<DelegationId, DelegationData>::new();

        for (delegation_id, delegation) in delegations {
            pool_delegation_shares.insert((pool_id, *delegation_id), *delegation.balance());
            delegation_balances.insert(*delegation_id, *delegation.balance());
            delegation_data.insert(
                *delegation_id,
                DelegationData::new(pool_id, delegation.spend_destination().clone()),
            );
        }

        let storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, pool_balances)]),
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        );

        Self {
            storage,
            delegation_rewards: Default::default(),
            pool_rewards: Default::default(),
        }
    }

    pub fn rewards_per_delegation(&self) -> &Vec<(DelegationId, Amount)> {
        &self.delegation_rewards
    }
}

impl PoSAccountingView for PoSAdapter {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Self::Error> {
        let db = PoSAccountingDB::new(&self.storage);
        db.pool_exists(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        let db = PoSAccountingDB::new(&self.storage);
        db.get_pool_data(pool_id)
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Amount, Self::Error> {
        let db = PoSAccountingDB::new(&self.storage);
        db.get_pool_balance(pool_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<pos_accounting::DelegationData>, Self::Error> {
        let db = PoSAccountingDB::new(&self.storage);
        db.get_delegation_data(delegation_id)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Amount, Self::Error> {
        let db = PoSAccountingDB::new(&self.storage);
        db.get_delegation_balance(delegation_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Amount, Self::Error> {
        let db = PoSAccountingDB::new(&self.storage);
        db.get_pool_delegation_share(pool_id, delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        let db = PoSAccountingDB::new(&self.storage);
        db.get_pool_delegations_shares(pool_id)
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
        let mut db = PoSAccountingDB::new(&mut self.storage);
        let mut delta = PoSAccountingDelta::new(&mut db);

        let _ = delta.delegate_staking(delegation_target, amount_to_delegate)?;

        let consumed = delta.consume();
        db.batch_write_delta(consumed)?;

        self.delegation_rewards.push((delegation_target, amount_to_delegate));

        Ok(())
    }

    fn decommission_pool(&mut self, _pool_id: PoolId) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }

    fn create_delegation_id(
        &mut self,
        _target_pool: PoolId,
        _delegation_id: DelegationId,
        _spend_key: Destination,
    ) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }

    fn delete_delegation_id(
        &mut self,
        _delegation_id: DelegationId,
    ) -> Result<(), pos_accounting::Error> {
        unimplemented!()
    }

    fn increase_staker_rewards(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<(), pos_accounting::Error> {
        let mut db = PoSAccountingDB::new(&mut self.storage);
        let mut delta = PoSAccountingDelta::new(&mut db);

        let _ = delta.increase_staker_rewards(pool_id, amount_to_add)?;

        let consumed = delta.consume();
        db.batch_write_delta(consumed)?;

        self.pool_rewards.insert(pool_id, amount_to_add);

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

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

use common::{
    chain::{DelegationId, Destination, PoolId},
    primitives::Amount,
};
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use strum::EnumCount as _;
use test_utils::random::{make_seedable_rng, Seed};

use super::create_pool_data;

use crate::{
    pool::{delegation::DelegationData, storage::PoSAccountingDB},
    storage::in_memory::InMemoryPoSAccounting,
    FlushablePoSAccountingView, PoSAccountingDelta, PoSAccountingOperations, PoSAccountingUndo,
    PoSAccountingView,
};

fn get_random_pool_id(rng: &mut impl Rng, storage: &InMemoryPoSAccounting) -> Option<PoolId> {
    let all_pool_data = storage.all_pool_data();
    (!all_pool_data.is_empty())
        .then(|| *all_pool_data.iter().nth(rng.gen_range(0..all_pool_data.len())).unwrap().0)
}

fn get_random_delegation_data(
    rng: &mut impl Rng,
    storage: &InMemoryPoSAccounting,
) -> Option<(DelegationId, DelegationData)> {
    let all_delegation_data = storage.all_delegation_data();
    (!all_delegation_data.is_empty()).then(|| {
        all_delegation_data
            .iter()
            .nth(rng.gen_range(0..all_delegation_data.len()))
            .map(|(id, data)| (*id, data.clone()))
            .unwrap()
    })
}

fn get_random_delegation_balance(
    rng: &mut impl Rng,
    storage: &InMemoryPoSAccounting,
) -> Option<(DelegationId, Amount)> {
    let all_delegation_balances = storage.all_delegation_balances();
    (!all_delegation_balances.is_empty()).then(|| {
        all_delegation_balances
            .iter()
            .nth(rng.gen_range(0..all_delegation_balances.len()))
            .map(|(id, balance)| (*id, *balance))
            .unwrap()
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simulation_test_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut undos = Vec::<PoSAccountingUndo>::new();

    let iterations_count = rng.gen_range(100..1000);

    for _ in 0..iterations_count {
        // collecting following random items every time is not efficient, because only single one of them might be used;
        // but in this way the borrows checker can be appeased because `PoSAccountingDB` requires `&mut storage`
        let random_pool = get_random_pool_id(&mut rng, &storage);
        let random_delegation = get_random_delegation_data(&mut rng, &storage);
        let random_delegation_balance = get_random_delegation_balance(&mut rng, &storage);

        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        perform_random_operation(
            &mut rng,
            &mut delta,
            &mut undos,
            random_pool,
            random_delegation,
            random_delegation_balance,
        );
        db.batch_write_delta(delta.consume()).unwrap();
        storage.check_consistency();
    }
}

fn perform_random_operation(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations<PoSAccountingUndo> + PoSAccountingView),
    undos: &mut Vec<PoSAccountingUndo>,
    random_pool: Option<PoolId>,
    random_delegation: Option<(DelegationId, DelegationData)>,
    random_delegation_balance: Option<(DelegationId, Amount)>,
) {
    // If it fires it means that number of actions in PoSAccountingOperations has changed
    // and the following match needs to be updated
    assert_eq!(PoSAccountingUndo::COUNT, 7);

    match rng.gen_range(0..11) {
        // create new pool
        0..=1 => {
            let pledge_amount = Amount::from_atoms(rng.gen_range(1000..10_000));
            let pool_data = create_pool_data(rng, Destination::AnyoneCanSpend, pledge_amount);
            let pool_id = PoolId::random_using(rng);

            let undo = op.create_pool(pool_id, pool_data).unwrap();
            undos.push(undo);
        }
        // decommission pool
        2 => {
            if let Some(pool_id) = random_pool {
                let undo = op.decommission_pool(pool_id).unwrap();
                undos.push(undo);
            }
        }
        // create delegation
        3..=4 => {
            if let Some(pool_id) = random_pool {
                let delegation_id = DelegationId::random_using(rng);

                let undo = op
                    .create_delegation_id(pool_id, delegation_id, Destination::AnyoneCanSpend)
                    .unwrap();
                undos.push(undo);
            }
        }
        // delegate staking
        5..=6 => {
            if let Some((delegation_id, delegation_data)) = random_delegation {
                // it's possible that after decommission pool the delegations are still there
                if op.pool_exists(*delegation_data.source_pool()).unwrap() {
                    let amount_to_delegate = Amount::from_atoms(rng.gen_range(1000..10_000));

                    let undo = op.delegate_staking(delegation_id, amount_to_delegate).unwrap();
                    undos.push(undo);
                }
            }
        }
        // spend share from delegation
        7 => {
            if let Some((delegation_id, balance)) = random_delegation_balance {
                let amount_to_spent = Amount::from_atoms(rng.gen_range(1..=balance.into_atoms()));

                let undo =
                    op.spend_share_from_delegation_id(delegation_id, amount_to_spent).unwrap();
                undos.push(undo);
            }
        }
        // increase staker reward
        8..=9 => {
            if let Some(pool_id) = random_pool {
                let amount_to_add = Amount::from_atoms(rng.gen_range(1000..10_000));

                let undo = op.increase_staker_rewards(pool_id, amount_to_add).unwrap();
                undos.push(undo);
            }
        }
        // delete delegation
        10 => {
            if let Some((delegation_id, delegation_data)) = random_delegation {
                if !op.pool_exists(*delegation_data.source_pool()).unwrap()
                    && op.get_delegation_balance(delegation_id).unwrap() == Amount::ZERO
                {
                    let undo = op.delete_delegation_id(delegation_id).unwrap();
                    undos.push(undo);
                }
            }
        }
        // undo
        11 => {
            if let Some(undo) = undos.pop() {
                op.undo(undo).unwrap();
            }
        }
        _ => panic!("Out of range"),
    };
}

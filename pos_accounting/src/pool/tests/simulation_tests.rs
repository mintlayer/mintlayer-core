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
    chain::{DelegationId, Destination, OutPoint, OutPointSourceId, PoolId},
    primitives::{Amount, Id, H256},
};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::create_pool_data;

use crate::{
    pool::{delegation::DelegationData, storage::PoSAccountingDB},
    storage::in_memory::InMemoryPoSAccounting,
    PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView,
};

fn random_outpoint0(rng: &mut impl Rng) -> OutPoint {
    let source_id = OutPointSourceId::Transaction(Id::new(H256::random_using(rng)));
    OutPoint::new(source_id, 0)
}

fn get_random_pool_id(rng: &mut impl Rng, storage: &InMemoryPoSAccounting) -> Option<PoolId> {
    let all_pool_data = storage.all_pool_data();
    if !all_pool_data.is_empty() {
        let (pool_id, _) = all_pool_data.iter().nth(rng.gen_range(0..all_pool_data.len())).unwrap();
        Some(*pool_id)
    } else {
        None
    }
}

fn get_random_delegation_data(
    rng: &mut impl Rng,
    storage: &InMemoryPoSAccounting,
) -> Option<(DelegationId, DelegationData)> {
    let all_delegation_data = storage.all_delegation_data();
    if !all_delegation_data.is_empty() {
        let (delegation_id, data) = all_delegation_data
            .iter()
            .nth(rng.gen_range(0..all_delegation_data.len()))
            .unwrap();
        Some((*delegation_id, data.clone()))
    } else {
        None
    }
}

fn get_random_delegation_balance(
    rng: &mut impl Rng,
    storage: &InMemoryPoSAccounting,
) -> Option<(DelegationId, Amount)> {
    let all_delegation_balances = storage.all_delegation_balances();
    if !all_delegation_balances.is_empty() {
        let (delegation_id, balance) = all_delegation_balances
            .iter()
            .nth(rng.gen_range(0..all_delegation_balances.len()))
            .unwrap();
        Some((*delegation_id, *balance))
    } else {
        None
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simulation_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    // FIXME: same for delta
    let mut undos: Vec<PoSAccountingUndo> = Default::default();

    let iterations_count = rng.gen_range(100..10_000);

    for _ in 0..iterations_count {
        match rng.gen_range(0..11) {
            0 | 1 => {
                let input0_outpoint = random_outpoint0(&mut rng);
                let pledge_amount = Amount::from_atoms(rng.gen_range(1000..10_000));
                let pool_data =
                    create_pool_data(&mut rng, Destination::AnyoneCanSpend, pledge_amount);

                let mut db = PoSAccountingDB::new(&mut storage);
                let (pool_id, undo) = db.create_pool(&input0_outpoint, pool_data).unwrap();
                println!("Creating pool: {}", pool_id);
                undos.push(undo);
            }
            2 => {
                let pool_id = get_random_pool_id(&mut rng, &storage);
                if let Some(pool_id) = pool_id {
                    println!("Decommissioning pool: {}", pool_id);
                    let mut db = PoSAccountingDB::new(&mut storage);
                    let undo = db.decommission_pool(pool_id).unwrap();
                    undos.push(undo);
                }
            }
            3 | 4 => {
                let pool_id = get_random_pool_id(&mut rng, &storage);
                if let Some(pool_id) = pool_id {
                    let input0_outpoint = random_outpoint0(&mut rng);

                    let mut db = PoSAccountingDB::new(&mut storage);
                    let (delegation_id, undo) = db
                        .create_delegation_id(
                            pool_id,
                            Destination::AnyoneCanSpend,
                            &input0_outpoint,
                        )
                        .unwrap();
                    println!(
                        "Creating delegation {0} for pool: {1}",
                        delegation_id, pool_id
                    );
                    undos.push(undo);
                }
            }
            5 | 6 => {
                let delegation_data = get_random_delegation_data(&mut rng, &storage);
                if let Some((delegation_id, delegation_data)) = delegation_data {
                    // it's possible that after decommission pool the delegations are still there
                    let mut db = PoSAccountingDB::new(&mut storage);
                    if db.pool_exists(*delegation_data.source_pool()).unwrap() {
                        let amount_to_delegate = Amount::from_atoms(rng.gen_range(1000..10_000));

                        println!("Delegating staking : {}", delegation_id);
                        let undo = db.delegate_staking(delegation_id, amount_to_delegate).unwrap();
                        undos.push(undo);
                    }
                }
            }
            7 => {
                let delegation_balance = get_random_delegation_balance(&mut rng, &storage);
                if let Some((delegation_id, balance)) = delegation_balance {
                    let amount_to_spent =
                        Amount::from_atoms(rng.gen_range(1..=balance.into_atoms()));

                    println!("Spending share from delegation : {}", delegation_id);
                    let mut db = PoSAccountingDB::new(&mut storage);
                    let undo =
                        db.spend_share_from_delegation_id(delegation_id, amount_to_spent).unwrap();
                    undos.push(undo);
                }
            }
            8 | 9 => {
                let pool_id = get_random_pool_id(&mut rng, &storage);
                if let Some(pool_id) = pool_id {
                    let amount_to_add = Amount::from_atoms(rng.gen_range(1000..10_000));

                    println!("Increasing pool balance: {}", pool_id);
                    let mut db = PoSAccountingDB::new(&mut storage);
                    let undo = db.increase_pool_pledge_amount(pool_id, amount_to_add).unwrap();
                    undos.push(undo);
                }
            }
            10 => {
                if let Some(undo) = undos.pop() {
                    println!("Undoing");
                    let mut db = PoSAccountingDB::new(&mut storage);
                    db.undo(undo).unwrap();
                }
            }
            _ => panic!("Out of range"),
        };
        storage.check_consistancy();
    }
}

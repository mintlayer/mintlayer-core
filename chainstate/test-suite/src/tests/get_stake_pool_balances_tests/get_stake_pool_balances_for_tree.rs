// Copyright (c) 2021-2024 RBB S.r.l
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

use rstest::rstest;

use chainstate::{BlockValidity, InMemoryBlockTree, InMemoryBlockTreeNodeId, InMemoryBlockTreeRef};
use chainstate_test_framework::{PoolBalances, TestFramework};
use common::{
    chain::{GenBlock, PoolId},
    primitives::{BlockHeight, Id, Idable},
};
use test_utils::random::{make_seedable_rng, Seed};

use super::helpers::{
    genesis_pool_id, make_test_framework, BalancesMapHolder, TestData, GENESIS_POOL_PLEDGE,
};

// Create the following block tree:
//             /----a1----a2----a3----a4----a5----a6
//             |----b1----b2
//             |     |----c1----c2
//             |     \----d1----d2
//             |
// G----m1----m2----m3----m4----m5----m6----m7----m8----!bb1
//                         \----e1----!bb2
//                               \----?bb
// and check pool balances at every step.
// Here bb1 and bb2 fail the "check block" stage and bb3 will only fail during reorg.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn basic_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework(&mut rng);
        let mut test_data = TestData::new(&mut tf);

        let initial_block_reward =
            tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::one());
        let genesis_id: Id<GenBlock> = tf.genesis().get_id().into();

        let pool0 = genesis_pool_id();

        let genesis_pool_balance = GENESIS_POOL_PLEDGE;
        let mut expected_balances = BTreeMap::from([(
            genesis_id,
            BTreeMap::from([(pool0, PoolBalances::new_same(genesis_pool_balance))]),
        )]);

        type ExpectedBalances = BTreeMap<Id<GenBlock>, BTreeMap<PoolId, PoolBalances>>;

        let do_check_balances = |tf: &TestFramework,
                                 test_data: &TestData,
                                 expected_balances: &ExpectedBalances,
                                 existing_pools: &[PoolId]| {
            check_balances(tf, expected_balances, existing_pools);
            check_balances_in_test_data(tf, test_data);
        };

        //------------------------------------------------------------------------------------------
        // Create the main chain

        let (m1_id, pool1, pool1_pledge) =
            test_data.make_new_pool(&mut tf, &mut rng, Some(genesis_id));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        expected_balances.insert(
            m1_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool1, PoolBalances::new_same(pool1_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1]);

        let (m2_id, pool2, pool2_pledge) =
            test_data.make_new_pool(&mut tf, &mut rng, Some(m1_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let genesis_pool_balance_after_m2 = genesis_pool_balance;
        let pool2_balance_after_m2 = pool2_pledge;
        let pool2_pledge_after_m2 = pool2_pledge;
        expected_balances.insert(
            m2_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool1, PoolBalances::new_same(pool1_pledge)),
                (pool2, PoolBalances::new_same(pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let m3_id = test_data.decommission_pool(&mut tf, &mut rng, &pool1, Some(m2_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        expected_balances.insert(
            m3_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new_same(pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (m4_id, delegation, delegated_anount) =
            test_data.create_delegation(&mut tf, &mut rng, &pool2, Some(m3_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_pledge + delegated_anount).unwrap();
        let genesis_pool_balance_after_m4 = genesis_pool_balance;
        let pool2_balance_after_m4 = pool2_balance;
        let pool2_pledge_after_m4 = pool2_pledge;
        expected_balances.insert(
            m4_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (m5_id, withdraw_amount) = test_data.withdraw_from_delegation(
            &mut tf,
            &mut rng,
            &pool2,
            &delegation,
            Some(m4_id.into()),
        );
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        expected_balances.insert(
            m5_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (m6_id, added_amount) =
            test_data.add_to_delegation(&mut tf, &mut rng, &pool2, &delegation, Some(m5_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance + added_amount).unwrap();
        expected_balances.insert(
            m6_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let m7_id = test_data.produce_trivial_block_with_pool(
            &mut tf,
            &mut rng,
            &genesis_pool_id(),
            Some(m6_id.into()),
        );
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        expected_balances.insert(
            m7_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let m8_id = test_data.produce_trivial_block_with_pool(
            &mut tf,
            &mut rng,
            &pool2,
            Some(m7_id.into()),
        );
        let pool2_balance = (pool2_balance + initial_block_reward).unwrap();
        let pool2_pledge = (pool2_pledge + initial_block_reward).unwrap();
        expected_balances.insert(
            m8_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let _bb1_id = test_data.produce_bad_block(&mut tf, &mut rng, Some(m8_id.into()));
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        //------------------------------------------------------------------------------------------
        // Create the "a" chain

        let genesis_pool_balance = genesis_pool_balance_after_m2;
        let pool2_balance = pool2_balance_after_m2;
        let pool2_pledge = pool2_pledge_after_m2;

        let a1_id = test_data.decommission_pool(&mut tf, &mut rng, &pool1, Some(m2_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        expected_balances.insert(
            a1_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new_same(pool2_balance)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (a2_id, delegation, delegated_anount) =
            test_data.create_delegation(&mut tf, &mut rng, &pool2, Some(a1_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance + delegated_anount).unwrap();
        expected_balances.insert(
            a2_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (a3_id, withdraw_amount) = test_data.withdraw_from_delegation(
            &mut tf,
            &mut rng,
            &pool2,
            &delegation,
            Some(a2_id.into()),
        );
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        expected_balances.insert(
            a3_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (a4_id, added_amount) =
            test_data.add_to_delegation(&mut tf, &mut rng, &pool2, &delegation, Some(a3_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance + added_amount).unwrap();
        expected_balances.insert(
            a4_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let a5_id = test_data.produce_trivial_block_with_pool(
            &mut tf,
            &mut rng,
            &genesis_pool_id(),
            Some(a4_id.into()),
        );
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        expected_balances.insert(
            a5_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let a6_id = test_data.produce_trivial_block_with_pool(
            &mut tf,
            &mut rng,
            &pool2,
            Some(a5_id.into()),
        );
        let pool2_balance = (pool2_balance + initial_block_reward).unwrap();
        let pool2_pledge = (pool2_pledge + initial_block_reward).unwrap();
        expected_balances.insert(
            a6_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        //------------------------------------------------------------------------------------------
        // Create the "b" chain

        let genesis_pool_balance = genesis_pool_balance_after_m2;
        let pool2_balance = pool2_balance_after_m2;
        let pool2_pledge = pool2_pledge_after_m2;

        let b1_id = test_data.decommission_pool(&mut tf, &mut rng, &pool1, Some(m2_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let genesis_pool_balance_after_b1 = genesis_pool_balance;
        let pool2_balance_after_b1 = pool2_balance;
        let pool2_pledge_after_b1 = pool2_pledge;
        expected_balances.insert(
            b1_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new_same(pool2_balance)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (b2_id, _delegation, delegated_anount) =
            test_data.create_delegation(&mut tf, &mut rng, &pool2, Some(b1_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance + delegated_anount).unwrap();
        expected_balances.insert(
            b2_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        //------------------------------------------------------------------------------------------
        // Create the "c" chain

        let genesis_pool_balance = genesis_pool_balance_after_b1;
        let pool2_balance = pool2_balance_after_b1;
        let pool2_pledge = pool2_pledge_after_b1;

        let (c1_id, delegation, delegated_anount) =
            test_data.create_delegation(&mut tf, &mut rng, &pool2, Some(b1_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance + delegated_anount).unwrap();
        expected_balances.insert(
            c1_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (c2_id, withdraw_amount) = test_data.withdraw_from_delegation(
            &mut tf,
            &mut rng,
            &pool2,
            &delegation,
            Some(c1_id.into()),
        );
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        expected_balances.insert(
            c2_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        //------------------------------------------------------------------------------------------
        // Create the "d" chain

        let genesis_pool_balance = genesis_pool_balance_after_b1;
        let pool2_balance = pool2_balance_after_b1;
        let pool2_pledge = pool2_pledge_after_b1;

        let (d1_id, delegation, delegated_anount) =
            test_data.create_delegation(&mut tf, &mut rng, &pool2, Some(b1_id.into()));
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance + delegated_anount).unwrap();
        expected_balances.insert(
            d1_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let (d2_id, withdraw_amount) = test_data.withdraw_from_delegation(
            &mut tf,
            &mut rng,
            &pool2,
            &delegation,
            Some(d1_id.into()),
        );
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        expected_balances.insert(
            d2_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        //------------------------------------------------------------------------------------------
        // Create e1 and 2 bad blocks on top of it

        let genesis_pool_balance = genesis_pool_balance_after_m4;
        let pool2_balance = pool2_balance_after_m4;
        let pool2_pledge = pool2_pledge_after_m4;

        let (e1_id, withdraw_amount) = test_data.withdraw_from_delegation(
            &mut tf,
            &mut rng,
            &pool2,
            &delegation,
            Some(m4_id.into()),
        );
        let genesis_pool_balance = (genesis_pool_balance + initial_block_reward).unwrap();
        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        expected_balances.insert(
            e1_id.into(),
            BTreeMap::from([
                (pool0, PoolBalances::new_same(genesis_pool_balance)),
                (pool2, PoolBalances::new(pool2_balance, pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let _bb2_id = test_data.produce_bad_block(&mut tf, &mut rng, Some(e1_id.into()));
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);

        let _bb3_id = test_data.produce_seemingly_ok_block(&mut tf, &mut rng, Some(e1_id.into()));
        do_check_balances(&tf, &test_data, &expected_balances, &[pool0, pool1, pool2]);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn randomized_test(#[case] seed: Seed) {
    use chainstate::BlockIndex;
    use randomness::{seq::IteratorRandom, Rng};

    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework(&mut rng);
        let mut test_data = TestData::new(&mut tf);

        let genesis_id: Id<GenBlock> = tf.genesis().get_id().into();
        let mut possible_parents = BTreeMap::<BlockHeight, BlockIndex>::new();

        for _i in 0..100 {
            // Randomly choose a parent from the top half of the chain.
            let parent_block_id = if let Some((best_height, _)) = possible_parents.last_key_value()
            {
                let block_id = *possible_parents
                    .range(BlockHeight::new(best_height.into_int() / 2)..)
                    .map(|(_, v)| v.block_id())
                    .choose(&mut rng)
                    .unwrap();
                block_id.into()
            } else {
                genesis_id
            };

            let mut new_block_id = None;

            if rng.gen_bool(0.3) {
                let (block_id, _, _) =
                    test_data.make_new_pool(&mut tf, &mut rng, Some(parent_block_id));
                new_block_id = Some(block_id);
            }

            if new_block_id.is_none() {
                match rng.gen_range(0..5) {
                    0 => {
                        if let Some(pool_id) =
                            test_data.random_pool_id(&tf, Some(parent_block_id), &mut rng)
                        {
                            let block_id = test_data.decommission_pool(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                Some(parent_block_id),
                            );
                            new_block_id = Some(block_id);
                        }
                    }
                    1 => {
                        if let Some(pool_id) =
                            test_data.random_pool_id(&tf, Some(parent_block_id), &mut rng)
                        {
                            let (block_id, _, _) = test_data.create_delegation(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                Some(parent_block_id),
                            );
                            new_block_id = Some(block_id);
                        }
                    }
                    2 => {
                        if let Some((pool_id, delegation_id)) = test_data
                            .random_pool_and_delegation_id(&tf, Some(parent_block_id), &mut rng)
                        {
                            let (block_id, _) = test_data.withdraw_from_delegation(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                &delegation_id,
                                Some(parent_block_id),
                            );
                            new_block_id = Some(block_id);
                        }
                    }
                    3 => {
                        if let Some((pool_id, delegation_id)) = test_data
                            .random_pool_and_delegation_id(&tf, Some(parent_block_id), &mut rng)
                        {
                            let (block_id, _) = test_data.add_to_delegation(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                &delegation_id,
                                Some(parent_block_id),
                            );
                            new_block_id = Some(block_id);
                        }
                    }

                    _ => {}
                }
            }

            if new_block_id.is_none() && rng.gen_bool(0.5) {
                if let Some(pool_id) =
                    test_data.random_pool_id(&tf, Some(parent_block_id), &mut rng)
                {
                    let block_id = test_data.produce_trivial_block_with_pool(
                        &mut tf,
                        &mut rng,
                        &pool_id,
                        Some(parent_block_id),
                    );
                    new_block_id = Some(block_id);
                }
            }

            if new_block_id.is_none() {
                let block_id = test_data.produce_trivial_block_with_pool(
                    &mut tf,
                    &mut rng,
                    &genesis_pool_id(),
                    Some(parent_block_id),
                );

                new_block_id = Some(block_id);
            }

            check_balances_in_test_data(&tf, &test_data);

            let new_block_index = tf.block_index(&new_block_id.unwrap());
            possible_parents.insert(new_block_index.block_height(), new_block_index);
        }
    });
}

fn get_balances_for_tree(
    tf: &TestFramework,
    pool_ids: &[PoolId],
    tree: InMemoryBlockTreeRef<'_>,
    include_tree_root_parent: bool,
) -> BTreeMap<Id<GenBlock>, BTreeMap<PoolId, PoolBalances>> {
    let balances = tf
        .chainstate
        .get_stake_pool_balances_for_tree(pool_ids, tree, include_tree_root_parent)
        .unwrap();

    balances
        .iter()
        .map(|(base_block_id, pool_to_balances_map)| {
            (
                *base_block_id,
                pool_to_balances_map
                    .iter()
                    .map(|(pool_id, balances)| {
                        (
                            *pool_id,
                            PoolBalances::new(balances.total_balance(), balances.staker_balance()),
                        )
                    })
                    .collect::<BTreeMap<_, _>>(),
            )
        })
        .collect::<BTreeMap<_, _>>()
}

fn get_node_tree(
    tf: &TestFramework,
) -> (
    InMemoryBlockTree,
    /*best_block_node_id:*/ InMemoryBlockTreeNodeId,
) {
    let best_block_id = tf.best_block_id().classify(tf.chain_config()).chain_block_id().unwrap();
    let trees = tf
        .chainstate
        .get_block_tree_top_starting_from_height(BlockHeight::new(0), BlockValidity::Any)
        .unwrap();
    let roots = trees.roots().collect::<BTreeMap<_, _>>();
    assert_eq!(roots.len(), 1);
    let (tree, best_block_node_id) = trees.find_node_id(&best_block_id).unwrap().unwrap();
    assert_eq!(tree.root_node_id(), *roots.first_key_value().unwrap().1);

    let root_block_id = *tree.root_block_index().unwrap().block_id();
    (
        trees.into_single_tree(&root_block_id).unwrap(),
        best_block_node_id,
    )
}

fn balances_with_root_parent_removed(
    mut balances: BTreeMap<Id<GenBlock>, BTreeMap<PoolId, PoolBalances>>,
    tree: InMemoryBlockTreeRef<'_>,
) -> BTreeMap<Id<GenBlock>, BTreeMap<PoolId, PoolBalances>> {
    balances.remove(tree.root_block_index().unwrap().prev_block_id());
    balances
}

fn check_balances_in_test_data(tf: &TestFramework, test_data: &TestData) {
    let all_pool_ids = test_data.collect_all_pool_ids();
    let (tree, _) = get_node_tree(tf);

    let balances = get_balances_for_tree(tf, &all_pool_ids, tree.as_ref(), true);
    let expected_balances = test_data
        .expected_balances()
        .iter()
        .filter_map(|(base_block, balances_holder)| {
            let balances = balances_holder.balances_map();
            (!balances.is_empty()).then(|| (*base_block, balances.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, expected_balances);

    let balances = get_balances_for_tree(tf, &all_pool_ids, tree.as_ref(), false);
    let expected_balances = balances_with_root_parent_removed(expected_balances, tree.as_ref());
    assert_eq!(balances, expected_balances);
}

fn check_balances(
    tf: &TestFramework,
    all_expected_balances: &BTreeMap<Id<GenBlock>, impl BalancesMapHolder>,
    existing_pools: &[PoolId],
) {
    let (tree, best_block_node_id) = get_node_tree(tf);
    let mut cur_mainchain_node_id = best_block_node_id;

    loop {
        let subtree = tree.subtree(cur_mainchain_node_id).unwrap();
        let balances = get_balances_for_tree(tf, existing_pools, subtree, true);

        let base_block_ids = std::iter::once(*subtree.root_block_index().unwrap().prev_block_id())
            .chain(subtree.all_block_indices_iter().filter_map(|block_index| {
                block_index.status().is_ok().then_some((*block_index.block_id()).into())
            }))
            .collect::<Vec<_>>();

        let expected_balances = base_block_ids
            .iter()
            .filter_map(|base_block_id| {
                let empty_map = BTreeMap::new();
                let balances = all_expected_balances
                    .get(base_block_id)
                    .map_or(&empty_map, |balances_holder| balances_holder.balances_map());
                (!balances.is_empty()).then(|| (*base_block_id, balances.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(balances, expected_balances);

        let balances = get_balances_for_tree(tf, existing_pools, subtree, false);
        let expected_balances = balances_with_root_parent_removed(expected_balances, subtree);
        assert_eq!(balances, expected_balances);

        if let Some(parent_node_id) = tree.get_parent(cur_mainchain_node_id).unwrap() {
            cur_mainchain_node_id = parent_node_id;
        } else {
            break;
        }
    }
}

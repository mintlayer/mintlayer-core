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

use chainstate_test_framework::{PoolBalances, TestFramework};
use common::{chain::PoolId, primitives::BlockHeight};
use randomness::Rng;
use test_utils::random::{make_seedable_rng, Seed};

use super::helpers::{genesis_pool_id, make_test_framework, BalancesMapHolder, TestData};

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

        let mut expected_balances = BTreeMap::new();

        type ExpectedBalances = BTreeMap<BlockHeight, BTreeMap<PoolId, PoolBalances>>;

        let do_check_balances = |tf: &TestFramework,
                                 test_data: &TestData,
                                 expected_balances: &ExpectedBalances,
                                 existing_pools: &[PoolId]| {
            check_balances(tf, expected_balances, existing_pools);
            check_balances_in_test_data(tf, test_data);
        };

        let (_, pool1, pool1_pledge) = test_data.make_new_pool(&mut tf, &mut rng, None);
        expected_balances.insert(
            BlockHeight::new(1),
            BTreeMap::from([(pool1, PoolBalances::new_same(pool1_pledge))]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1]);

        let (_, pool2, pool2_pledge) = test_data.make_new_pool(&mut tf, &mut rng, None);
        expected_balances.insert(
            BlockHeight::new(2),
            BTreeMap::from([
                (pool1, PoolBalances::new_same(pool1_pledge)),
                (pool2, PoolBalances::new_same(pool2_pledge)),
            ]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1, pool2]);

        test_data.decommission_pool(&mut tf, &mut rng, &pool1, None);
        expected_balances.insert(
            BlockHeight::new(3),
            BTreeMap::from([(pool2, PoolBalances::new_same(pool2_pledge))]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1, pool2]);

        let (_, delegation, delegated_anount) =
            test_data.create_delegation(&mut tf, &mut rng, &pool2, None);
        let pool2_balance = (pool2_pledge + delegated_anount).unwrap();
        expected_balances.insert(
            BlockHeight::new(4),
            BTreeMap::from([(pool2, PoolBalances::new(pool2_balance, pool2_pledge))]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1, pool2]);

        let (_, withdraw_amount) =
            test_data.withdraw_from_delegation(&mut tf, &mut rng, &pool2, &delegation, None);
        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        expected_balances.insert(
            BlockHeight::new(5),
            BTreeMap::from([(pool2, PoolBalances::new(pool2_balance, pool2_pledge))]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1, pool2]);

        let (_, added_amount) =
            test_data.add_to_delegation(&mut tf, &mut rng, &pool2, &delegation, None);
        let pool2_balance = (pool2_balance + added_amount).unwrap();
        expected_balances.insert(
            BlockHeight::new(6),
            BTreeMap::from([(pool2, PoolBalances::new(pool2_balance, pool2_pledge))]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1, pool2]);

        test_data.produce_trivial_block_with_pool(&mut tf, &mut rng, &genesis_pool_id(), None);
        expected_balances.insert(
            BlockHeight::new(7),
            BTreeMap::from([(pool2, PoolBalances::new(pool2_balance, pool2_pledge))]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1, pool2]);

        test_data.produce_trivial_block_with_pool(&mut tf, &mut rng, &pool2, None);
        let pool2_balance = (pool2_balance + initial_block_reward).unwrap();
        let pool2_pledge = (pool2_pledge + initial_block_reward).unwrap();
        expected_balances.insert(
            BlockHeight::new(8),
            BTreeMap::from([(pool2, PoolBalances::new(pool2_balance, pool2_pledge))]),
        );
        do_check_balances(&tf, &test_data, &expected_balances, &[pool1, pool2]);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn randomized_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework(&mut rng);
        let mut test_data = TestData::new(&mut tf);

        for _ in 0..100 {
            let mut did_something = false;
            match rng.gen_range(0..5) {
                0 => {
                    let _ = test_data.make_new_pool(&mut tf, &mut rng, None);
                    did_something = true;
                }
                1 => {
                    if rng.gen_bool(0.5) {
                        if let Some(pool_id) = test_data.random_pool_id(&tf, None, &mut rng) {
                            test_data.decommission_pool(&mut tf, &mut rng, &pool_id, None);
                            did_something = true;
                        }
                    }
                }
                2 => {
                    if rng.gen_bool(0.5) {
                        if let Some(pool_id) = test_data.random_pool_id(&tf, None, &mut rng) {
                            let _ = test_data.create_delegation(&mut tf, &mut rng, &pool_id, None);
                            did_something = true;
                        }
                    }
                }
                3 => {
                    if rng.gen_bool(0.5) {
                        if let Some((pool_id, delegation_id)) =
                            test_data.random_pool_and_delegation_id(&tf, None, &mut rng)
                        {
                            let _ = test_data.withdraw_from_delegation(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                &delegation_id,
                                None,
                            );
                            did_something = true;
                        }
                    }
                }
                _ => {
                    if rng.gen_bool(0.5) {
                        if let Some((pool_id, delegation_id)) =
                            test_data.random_pool_and_delegation_id(&tf, None, &mut rng)
                        {
                            let _ = test_data.add_to_delegation(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                &delegation_id,
                                None,
                            );
                            did_something = true;
                        }
                    }
                }
            }

            if !did_something && rng.gen_bool(0.5) {
                if let Some(pool_id) = test_data.random_pool_id(&tf, None, &mut rng) {
                    test_data.produce_trivial_block_with_pool(&mut tf, &mut rng, &pool_id, None);
                    did_something = true;
                }
            }

            if !did_something {
                test_data.produce_trivial_block_with_pool(
                    &mut tf,
                    &mut rng,
                    &genesis_pool_id(),
                    None,
                );
            }

            check_balances_in_test_data(&tf, &test_data);
        }
    });
}

fn get_balances_at_heights(
    tf: &TestFramework,
    pool_ids: &[PoolId],
    min_height: Option<u64>,
    max_height: Option<u64>,
) -> BTreeMap<BlockHeight, BTreeMap<PoolId, PoolBalances>> {
    let min_height = BlockHeight::new(min_height.unwrap_or(0));
    let bb_height = tf.best_block_index().block_height();
    let max_height = max_height.map_or(bb_height, BlockHeight::new);

    let balances = tf
        .chainstate
        .get_stake_pool_balances_at_heights(pool_ids, min_height, max_height)
        .unwrap();

    balances
        .iter()
        .map(|(height, pool_to_balances_map)| {
            (
                *height,
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

fn get_cur_balances(tf: &TestFramework, pool_ids: &[PoolId]) -> BTreeMap<PoolId, PoolBalances> {
    let mut result = BTreeMap::new();

    for pool_id in pool_ids {
        let pool_balance = tf.chainstate.get_stake_pool_balance(*pool_id).unwrap();
        let pool_data = tf.chainstate.get_stake_pool_data(*pool_id).unwrap();

        match (pool_balance, pool_data) {
            (Some(balance), Some(data)) => {
                result.insert(
                    *pool_id,
                    PoolBalances::new(balance, data.staker_balance().unwrap()),
                );
            }
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                panic!("Pool balance presence is inconsistent with pool data's")
            }
        }
    }

    result
}

fn check_balances_in_test_data(tf: &TestFramework, test_data: &TestData) {
    let all_pool_ids = test_data.collect_all_pool_ids();

    let expected_balances = test_data
        .expected_balances()
        .iter()
        .filter_map(|(base_block_id, balances_holder)| {
            tf.chainstate.get_block_height_in_main_chain(base_block_id).unwrap().and_then(
                |height| {
                    let balances = balances_holder.balances_map();

                    (!balances.is_empty()).then(|| (height, balances.clone()))
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    // Note: since check_balances checks all possible height combinations, calling it here would make
    // the randomized test extremely slow. So we don't do it.

    let actual_balances = get_balances_at_heights(tf, &all_pool_ids, None, None);
    let cur_actual_balances = get_cur_balances(tf, &all_pool_ids);

    let bb_height = tf.best_block_index().block_height();
    let empty_map = BTreeMap::new();
    let actual_balances_at_bb_height = actual_balances.get(&bb_height).unwrap_or(&empty_map);
    assert_eq!(*actual_balances_at_bb_height, cur_actual_balances);

    assert_eq!(actual_balances, expected_balances);
}

fn check_balances(
    tf: &TestFramework,
    expected_balances: &BTreeMap<BlockHeight, BTreeMap<PoolId, PoolBalances>>,
    existing_pools: &[PoolId],
) {
    let last_height = tf.best_block_index().block_height().into_int();
    let cur_actual_balances = get_cur_balances(tf, existing_pools);

    let bb_height = tf.best_block_index().block_height();

    for min_height in 0..=last_height {
        for max_height in min_height..=last_height {
            let actual_balances_for_range =
                get_balances_at_heights(tf, existing_pools, Some(min_height), Some(max_height));

            let expected_balances_for_range = expected_balances
                .range(BlockHeight::new(min_height)..=BlockHeight::new(max_height))
                .filter(|(_, balances)| (!balances.is_empty()))
                .map(|(height, balances)| (*height, balances.clone()))
                .collect::<BTreeMap<_, _>>();

            assert_eq!(
                actual_balances_for_range, expected_balances_for_range,
                "Balances differ; min_height = {min_height}, max_height = {max_height}"
            );

            if max_height == last_height {
                let empty_map = BTreeMap::new();
                let actual_balances_at_bb_height =
                    actual_balances_for_range.get(&bb_height).unwrap_or(&empty_map);
                assert_eq!(*actual_balances_at_bb_height, cur_actual_balances);
            }
        }
    }
}

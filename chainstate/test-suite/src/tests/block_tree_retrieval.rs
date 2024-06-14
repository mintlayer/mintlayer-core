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

use std::collections::{BTreeMap, BTreeSet};

use chainstate::{BlockValidity, InMemoryBlockTreeRef, InMemoryBlockTrees};
use itertools::Itertools;
use rstest::rstest;

use chainstate_test_framework::TestFramework;
use chainstate_types::BlockValidationStage;
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, GenBlock},
    primitives::{BlockHeight, Id, Idable},
};
use test_utils::random::{make_seedable_rng, Seed};

use crate::tests::helpers::{
    block_creation_helpers::{
        process_block, process_block_spend_tx, process_block_split_parent_reward,
    },
    block_status_helpers::{
        assert_bad_blocks_at_stage, assert_blocks_with_bad_parent_at_stage,
        assert_fully_valid_blocks, assert_ok_blocks_at_stage,
    },
};
use logging::log;
use utils::sorted::Sorted;

// Create the following block tree:
// /----a0----a1
// G----m0----m1----m2
//      \-----b0---!b1---!b2
//                   \---!c1
// where b1 is invalid and persisted and b2 is invalid and non-persisted, checking leaf blocks at each step.
// After that, check that get_block_id_tree_as_list, get_block_tree_top_starting_from_height and
// get_block_tree_top_starting_from_timestamp return what they are supposed to.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn block_tree_retrieval(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        assert_leaves(&tf, BlockHeight::new(0), &[]);
        assert_leaves(&tf, BlockHeight::new(1), &[]);

        // The block timestamps will be as follows:
        // G--m0--m1--m2
        //    a0------a1
        //        b0------b1--b2
        //                        c1

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        assert_leaves(&tf, BlockHeight::new(0), &[m0_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m0_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[]);

        let (a0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        assert_leaves(&tf, BlockHeight::new(0), &[m0_id, a0_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m0_id, a0_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[]);

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());
        assert_leaves(&tf, BlockHeight::new(0), &[m1_id, a0_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m1_id, a0_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[m1_id]);
        assert_leaves(&tf, BlockHeight::new(3), &[]);

        let (b0_id, b0_tx_id, result) =
            process_block_split_parent_reward(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());
        assert_leaves(&tf, BlockHeight::new(0), &[m1_id, a0_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m1_id, a0_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[m1_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(3), &[]);

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (a1_id, result) = process_block(&mut tf, &a0_id.into(), &mut rng);
        assert!(result.is_ok());
        assert_leaves(&tf, BlockHeight::new(0), &[m1_id, a1_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m1_id, a1_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[m1_id, a1_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(3), &[]);

        let (m2_id, result) = process_block(&mut tf, &m1_id.into(), &mut rng);
        assert!(result.is_ok());
        assert_leaves(&tf, BlockHeight::new(0), &[m2_id, a1_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m2_id, a1_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[m2_id, a1_id, b0_id]);
        assert_leaves(&tf, BlockHeight::new(3), &[m2_id]);
        assert_leaves(&tf, BlockHeight::new(4), &[]);

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (b1_id, result) =
            process_block_spend_tx(&mut tf, &b0_id.into(), &b0_tx_id, 1, &mut rng);
        assert!(result.is_ok());
        assert_leaves(&tf, BlockHeight::new(0), &[m2_id, a1_id, b1_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m2_id, a1_id, b1_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[m2_id, a1_id, b1_id]);
        assert_leaves(&tf, BlockHeight::new(3), &[m2_id, b1_id]);
        assert_leaves(&tf, BlockHeight::new(4), &[]);

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (b2_id, result) = process_block(&mut tf, &b1_id.into(), &mut rng);
        assert!(result.is_err());
        assert_leaves(&tf, BlockHeight::new(0), &[m2_id, a1_id, b2_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m2_id, a1_id, b2_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[m2_id, a1_id, b2_id]);
        assert_leaves(&tf, BlockHeight::new(3), &[m2_id, b2_id]);
        assert_leaves(&tf, BlockHeight::new(4), &[b2_id]);
        assert_leaves(&tf, BlockHeight::new(5), &[]);

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (c1_id, result) = process_block(&mut tf, &b1_id.into(), &mut rng);
        assert!(result.is_err());
        assert_leaves(&tf, BlockHeight::new(0), &[m2_id, a1_id, b2_id, c1_id]);
        assert_leaves(&tf, BlockHeight::new(1), &[m2_id, a1_id, b2_id, c1_id]);
        assert_leaves(&tf, BlockHeight::new(2), &[m2_id, a1_id, b2_id, c1_id]);
        assert_leaves(&tf, BlockHeight::new(3), &[m2_id, b2_id, c1_id]);
        assert_leaves(&tf, BlockHeight::new(4), &[b2_id, c1_id]);
        assert_leaves(&tf, BlockHeight::new(5), &[]);

        log::debug!("m0_id = {m0_id}, m1_id = {m1_id}, m2_id = {m2_id}, a0_id = {a0_id}, a1_id = {a1_id}, b0_id = {b0_id}, b1_id = {b1_id}, b2_id = {b2_id}, c1_id = {c1_id}");

        // Sanity check - ensure that all blocks are valid, except b1 and b2, and that b2 and c1 are not persisted.
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id, m2_id]);
        assert_ok_blocks_at_stage(
            &tf,
            &[a0_id, a1_id, b0_id],
            BlockValidationStage::CheckBlockOk,
        );
        assert_bad_blocks_at_stage(&tf, &[b1_id], BlockValidationStage::CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &[b2_id], BlockValidationStage::CheckBlockOk);
        // Note: c1 was added when its parent was already found to be invalid, so its validation will fail earlier
        // than b2's.
        assert_bad_blocks_at_stage(&tf, &[c1_id], BlockValidationStage::Unchecked);

        let block_id_tree_as_list = tf.chainstate.get_block_id_tree_as_list().unwrap();
        assert_eq!(
            block_id_tree_as_list.sorted(),
            [m0_id, m1_id, m2_id, a0_id, a1_id, b0_id, b1_id]
                .into_iter()
                .sorted()
                .collect_vec()
        );
        assert!(!tf.block_index(&b2_id).is_persisted());
        assert!(!tf.block_index(&c1_id).is_persisted());

        // BlockValidity::Ok
        assert_block_tree_top_by_height(&tf, 5.into(), BlockValidity::Ok, &[]);
        assert_block_tree_top_by_height(&tf, 4.into(), BlockValidity::Ok, &[]);
        assert_block_tree_top_by_height(&tf, 3.into(), BlockValidity::Ok, &[(3.into(), &[m2_id])]);
        assert_block_tree_top_by_height(
            &tf,
            2.into(),
            BlockValidity::Ok,
            &[(3.into(), &[m2_id]), (2.into(), &[m1_id, a1_id, b0_id])],
        );
        assert_block_tree_top_by_height(
            &tf,
            1.into(),
            BlockValidity::Ok,
            &[
                (3.into(), &[m2_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
                (1.into(), &[m0_id, a0_id]),
            ],
        );
        assert_block_tree_top_by_height(
            &tf,
            0.into(),
            BlockValidity::Ok,
            &[
                (3.into(), &[m2_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
                (1.into(), &[m0_id, a0_id]),
            ],
        );

        // BlockValidity::Persisted
        assert_block_tree_top_by_height(&tf, 5.into(), BlockValidity::Persisted, &[]);
        assert_block_tree_top_by_height(&tf, 4.into(), BlockValidity::Persisted, &[]);
        assert_block_tree_top_by_height(
            &tf,
            3.into(),
            BlockValidity::Persisted,
            &[(3.into(), &[m2_id, b1_id])],
        );
        assert_block_tree_top_by_height(
            &tf,
            2.into(),
            BlockValidity::Persisted,
            &[(3.into(), &[m2_id, b1_id]), (2.into(), &[m1_id, a1_id, b0_id])],
        );
        assert_block_tree_top_by_height(
            &tf,
            1.into(),
            BlockValidity::Persisted,
            &[
                (3.into(), &[m2_id, b1_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
                (1.into(), &[m0_id, a0_id]),
            ],
        );
        assert_block_tree_top_by_height(
            &tf,
            0.into(),
            BlockValidity::Persisted,
            &[
                (3.into(), &[m2_id, b1_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
                (1.into(), &[m0_id, a0_id]),
            ],
        );

        // BlockValidity::Any
        assert_block_tree_top_by_height(&tf, 5.into(), BlockValidity::Any, &[]);
        assert_block_tree_top_by_height(
            &tf,
            4.into(),
            BlockValidity::Any,
            &[(4.into(), &[b2_id, c1_id])],
        );
        assert_block_tree_top_by_height(
            &tf,
            3.into(),
            BlockValidity::Any,
            &[(4.into(), &[b2_id, c1_id]), (3.into(), &[m2_id, b1_id])],
        );
        assert_block_tree_top_by_height(
            &tf,
            2.into(),
            BlockValidity::Any,
            &[
                (4.into(), &[b2_id, c1_id]),
                (3.into(), &[m2_id, b1_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
            ],
        );
        assert_block_tree_top_by_height(
            &tf,
            1.into(),
            BlockValidity::Any,
            &[
                (4.into(), &[b2_id, c1_id]),
                (3.into(), &[m2_id, b1_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
                (1.into(), &[m0_id, a0_id]),
            ],
        );
        assert_block_tree_top_by_height(
            &tf,
            0.into(),
            BlockValidity::Any,
            &[
                (4.into(), &[b2_id, c1_id]),
                (3.into(), &[m2_id, b1_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
                (1.into(), &[m0_id, a0_id]),
            ],
        );

        // Sanity check: ensure timestamps are as expected.
        let ts0 = tf.genesis().timestamp();
        let ts1 = tf.block_index(&m0_id).block_timestamp();
        assert_eq!(ts1, tf.block_index(&a0_id).block_timestamp());
        let ts2 = tf.block_index(&m1_id).block_timestamp();
        assert_eq!(ts2, tf.block_index(&b0_id).block_timestamp());
        let ts3 = tf.block_index(&m2_id).block_timestamp();
        assert_eq!(ts3, tf.block_index(&a1_id).block_timestamp());
        let ts4 = tf.block_index(&b1_id).block_timestamp();
        let ts5 = tf.block_index(&b2_id).block_timestamp();
        let ts6 = tf.block_index(&c1_id).block_timestamp();
        assert!(ts6 > ts5 && ts5 > ts4 && ts4 > ts3 && ts3 > ts2 && ts2 > ts1 && ts1 > ts0);

        // BlockValidity::Ok
        assert_block_tree_top_by_timestamp(
            &tf,
            ts6.add_int_seconds(1).unwrap(),
            BlockValidity::Ok,
            &[],
        );
        assert_block_tree_top_by_timestamp(&tf, ts6, BlockValidity::Ok, &[]);
        assert_block_tree_top_by_timestamp(&tf, ts5, BlockValidity::Ok, &[]);
        assert_block_tree_top_by_timestamp(&tf, ts4, BlockValidity::Ok, &[]);
        assert_block_tree_top_by_timestamp(&tf, ts3, BlockValidity::Ok, &[(ts3, &[m2_id, a1_id])]);
        assert_block_tree_top_by_timestamp(
            &tf,
            ts2,
            BlockValidity::Ok,
            &[(ts3, &[m2_id, a1_id]), (ts2, &[m1_id, b0_id])],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts1,
            BlockValidity::Ok,
            &[(ts3, &[m2_id, a1_id]), (ts2, &[m1_id, b0_id]), (ts1, &[m0_id, a0_id])],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts0,
            BlockValidity::Ok,
            &[(ts3, &[m2_id, a1_id]), (ts2, &[m1_id, b0_id]), (ts1, &[m0_id, a0_id])],
        );

        // BlockValidity::Persisted
        assert_block_tree_top_by_timestamp(
            &tf,
            ts6.add_int_seconds(1).unwrap(),
            BlockValidity::Persisted,
            &[],
        );
        assert_block_tree_top_by_timestamp(&tf, ts6, BlockValidity::Persisted, &[]);
        assert_block_tree_top_by_timestamp(&tf, ts5, BlockValidity::Persisted, &[]);
        assert_block_tree_top_by_timestamp(&tf, ts4, BlockValidity::Persisted, &[(ts4, &[b1_id])]);
        assert_block_tree_top_by_timestamp(
            &tf,
            ts3,
            BlockValidity::Persisted,
            &[(ts4, &[b1_id]), (ts3, &[m2_id, a1_id])],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts2,
            BlockValidity::Persisted,
            &[(ts4, &[b1_id]), (ts3, &[m2_id, a1_id]), (ts2, &[m1_id, b0_id])],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts1,
            BlockValidity::Persisted,
            &[
                (ts4, &[b1_id]),
                (ts3, &[m2_id, a1_id]),
                (ts2, &[m1_id, b0_id]),
                (ts1, &[m0_id, a0_id]),
            ],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts0,
            BlockValidity::Persisted,
            &[
                (ts4, &[b1_id]),
                (ts3, &[m2_id, a1_id]),
                (ts2, &[m1_id, b0_id]),
                (ts1, &[m0_id, a0_id]),
            ],
        );

        // BlockValidity::Any
        assert_block_tree_top_by_timestamp(
            &tf,
            ts6.add_int_seconds(1).unwrap(),
            BlockValidity::Any,
            &[],
        );
        assert_block_tree_top_by_timestamp(&tf, ts6, BlockValidity::Any, &[(ts6, &[c1_id])]);
        assert_block_tree_top_by_timestamp(
            &tf,
            ts5,
            BlockValidity::Any,
            &[(ts6, &[c1_id]), (ts5, &[b2_id])],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts4,
            BlockValidity::Any,
            &[(ts6, &[c1_id]), (ts5, &[b2_id]), (ts4, &[b1_id])],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts3,
            BlockValidity::Any,
            &[(ts6, &[c1_id]), (ts5, &[b2_id]), (ts4, &[b1_id]), (ts3, &[m2_id, a1_id])],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts2,
            BlockValidity::Any,
            &[
                (ts6, &[c1_id]),
                (ts5, &[b2_id]),
                (ts4, &[b1_id]),
                (ts3, &[m2_id, a1_id]),
                (ts2, &[m1_id, b0_id]),
            ],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts1,
            BlockValidity::Any,
            &[
                (ts6, &[c1_id]),
                (ts5, &[b2_id]),
                (ts4, &[b1_id]),
                (ts3, &[m2_id, a1_id]),
                (ts2, &[m1_id, b0_id]),
                (ts1, &[m0_id, a0_id]),
            ],
        );
        assert_block_tree_top_by_timestamp(
            &tf,
            ts0,
            BlockValidity::Any,
            &[
                (ts6, &[c1_id]),
                (ts5, &[b2_id]),
                (ts4, &[b1_id]),
                (ts3, &[m2_id, a1_id]),
                (ts2, &[m1_id, b0_id]),
                (ts1, &[m0_id, a0_id]),
            ],
        );
    });
}

fn assert_leaves(tf: &TestFramework, min_height: BlockHeight, expected: &[Id<Block>]) {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let actual = tf.leaf_block_ids(min_height);
    assert_eq!(actual, expected);
}

fn check_tree_consistency(tree: InMemoryBlockTreeRef<'_>) {
    // Check that the root has no parent.
    assert!(tree.get_parent(tree.root_node_id()).unwrap().is_none());

    for child_node_id in tree.all_child_node_ids_iter() {
        let parent_node_id = tree.get_parent(child_node_id).unwrap().unwrap();
        let child_block_index = tree.get_block_index(child_node_id).unwrap();
        let parent_block_index = tree.get_block_index(parent_node_id).unwrap();
        assert_eq!(
            child_block_index.prev_block_id(),
            <&_ as Into<&Id<GenBlock>>>::into(parent_block_index.block_id())
        );
    }
}

fn check_trees_consistency(trees: &InMemoryBlockTrees) {
    for tree in trees.trees_iter() {
        check_tree_consistency(tree);
    }
}

fn assert_block_tree_top_by_height(
    tf: &TestFramework,
    start_from: BlockHeight,
    block_validity: BlockValidity,
    expected: &[(BlockHeight, &[Id<Block>])],
) {
    let expected = expected
        .iter()
        .map(|(height, ids)| (*height, ids.iter().copied().collect::<BTreeSet<_>>()))
        .collect::<BTreeMap<_, _>>();

    let actual_trees = tf
        .chainstate
        .get_block_tree_top_starting_from_height(start_from, block_validity)
        .unwrap();
    check_trees_consistency(&actual_trees);

    let actual = actual_trees.as_by_height_block_id_map().unwrap();

    assert_eq!(actual, expected);
}

fn assert_block_tree_top_by_timestamp(
    tf: &TestFramework,
    start_from: BlockTimestamp,
    block_validity: BlockValidity,
    expected: &[(BlockTimestamp, &[Id<Block>])],
) {
    let expected = expected
        .iter()
        .map(|(height, ids)| (*height, ids.iter().copied().collect::<BTreeSet<_>>()))
        .collect::<BTreeMap<_, _>>();

    let actual_trees = tf
        .chainstate
        .get_block_tree_top_starting_from_timestamp(start_from, block_validity)
        .unwrap();
    check_trees_consistency(&actual_trees);

    let actual = actual_trees.as_by_timestamp_block_id_map().unwrap();

    assert_eq!(actual, expected);
}

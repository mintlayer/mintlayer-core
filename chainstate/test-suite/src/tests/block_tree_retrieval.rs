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

        //------------------------------------------------------------------------------------------
        // block_tree_top_by_height

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

        //------------------------------------------------------------------------------------------
        // block_tree_top_by_timestamp

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

// Test connect_block_tree.
// The following block tree will be created:
// /----a0----a1
// G----m0----m1----m2
//      \-----b0----b1----b2
//                   \----c1
// Timestamp-wise, the tree will look as follows:
// ts0  ts1  ts2  ts3  ts4  ts5  ts6
// /----a0--------a1
// G----m0---m1---m2
//      \---------b0----b1---b2
//                      \--------c1
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_block_tree(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (a0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (b0_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());
        let (a1_id, result) = process_block(&mut tf, &a0_id.into(), &mut rng);
        assert!(result.is_ok());
        let (m2_id, result) = process_block(&mut tf, &m1_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (b1_id, result) = process_block(&mut tf, &b0_id.into(), &mut rng);
        assert!(result.is_ok());
        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (b2_id, result) = process_block(&mut tf, &b1_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (c1_id, result) = process_block(&mut tf, &b1_id.into(), &mut rng);
        assert!(result.is_ok());

        log::debug!("m0_id = {m0_id}, m1_id = {m1_id}, m2_id = {m2_id}, a0_id = {a0_id}, a1_id = {a1_id}, b0_id = {b0_id}, b1_id = {b1_id}, b2_id = {b2_id}, c1_id = {c1_id}");

        // Sanity check: ensure timestamps are as expected.
        let ts0 = tf.genesis().timestamp();
        let ts1 = tf.block_index(&m0_id).block_timestamp();
        assert_eq!(ts1, tf.block_index(&a0_id).block_timestamp());
        let ts2 = tf.block_index(&m1_id).block_timestamp();
        let ts3 = tf.block_index(&m2_id).block_timestamp();
        assert_eq!(ts3, tf.block_index(&b0_id).block_timestamp());
        assert_eq!(ts3, tf.block_index(&a1_id).block_timestamp());
        let ts4 = tf.block_index(&b1_id).block_timestamp();
        let ts5 = tf.block_index(&b2_id).block_timestamp();
        let ts6 = tf.block_index(&c1_id).block_timestamp();
        assert!(ts6 > ts5 && ts5 > ts4 && ts4 > ts3 && ts3 > ts2 && ts2 > ts1 && ts1 > ts0);

        //------------------------------------------------------------------------------------------

        // Start from the height 4.
        let trees = tf
            .chainstate
            .get_block_tree_top_starting_from_height(4.into(), BlockValidity::Any)
            .unwrap();
        let orig_expected_data: &[(BlockHeight, &[Id<Block>])] = &[(4.into(), &[b2_id, c1_id])];
        assert_height_data_for_trees(&tf, &trees, orig_expected_data);

        // Specifying too big a minimum height has no effect.
        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 5.into()).unwrap();
        assert_height_data_for_trees(&tf, &connected_trees, orig_expected_data);

        // Specifying minimum height which is the same as root's height has no effect.
        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 4.into()).unwrap();
        assert_height_data_for_trees(&tf, &connected_trees, orig_expected_data);

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 3.into()).unwrap();
        assert_height_data_for_trees(
            &tf,
            &connected_trees,
            &[(3.into(), &[b1_id]), (4.into(), &[b2_id, c1_id])],
        );

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 2.into()).unwrap();
        assert_height_data_for_trees(
            &tf,
            &connected_trees,
            &[(2.into(), &[b0_id]), (3.into(), &[b1_id]), (4.into(), &[b2_id, c1_id])],
        );

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 1.into()).unwrap();
        let expected_data_for_1: &[(BlockHeight, &[Id<Block>])] = &[
            (1.into(), &[m0_id]),
            (2.into(), &[b0_id]),
            (3.into(), &[b1_id]),
            (4.into(), &[b2_id, c1_id]),
        ];
        assert_height_data_for_trees(&tf, &connected_trees, expected_data_for_1);

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 0.into()).unwrap();
        assert_height_data_for_trees(&tf, &connected_trees, expected_data_for_1);

        // Now do the same starting from height 2.
        let trees = tf
            .chainstate
            .get_block_tree_top_starting_from_height(2.into(), BlockValidity::Any)
            .unwrap();
        let orig_expected_data: &[(BlockHeight, &[Id<Block>])] = &[
            (4.into(), &[b2_id, c1_id]),
            (3.into(), &[m2_id, b1_id]),
            (2.into(), &[m1_id, a1_id, b0_id]),
        ];
        assert_height_data_for_trees(&tf, &trees, orig_expected_data);

        // Specifying too big a minimum height has no effect.
        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 3.into()).unwrap();
        assert_height_data_for_trees(&tf, &connected_trees, orig_expected_data);

        // Specifying minimum height which is the same as roots' height has no effect.
        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 2.into()).unwrap();
        assert_height_data_for_trees(&tf, &connected_trees, orig_expected_data);

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 1.into()).unwrap();
        let expected_data_for_1: &[(BlockHeight, &[Id<Block>])] = &[
            (4.into(), &[b2_id, c1_id]),
            (3.into(), &[m2_id, b1_id]),
            (2.into(), &[m1_id, a1_id, b0_id]),
            (1.into(), &[m0_id, a0_id]),
        ];
        assert_height_data_for_trees(&tf, &connected_trees, expected_data_for_1);

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 0.into()).unwrap();
        assert_height_data_for_trees(&tf, &connected_trees, expected_data_for_1);

        //------------------------------------------------------------------------------------------

        // Start from the timestamp ts3.

        // The obtained trees will be as follows ('h' means height):
        // h2    h3    h4
        // a1
        //       m2
        // b0----b1----b2
        //        \----c1

        let trees = tf
            .chainstate
            .get_block_tree_top_starting_from_timestamp(ts3, BlockValidity::Any)
            .unwrap();
        assert_height_data_for_trees(
            &tf,
            &trees,
            &[
                (2.into(), &[a1_id, b0_id]),
                (3.into(), &[m2_id, b1_id]),
                (4.into(), &[b2_id, c1_id]),
            ],
        );

        // With the minimum height of 2 try_connect_block_trees will try to extend the m chain adding m1 to it,
        // but then stop at height 2.
        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 2.into()).unwrap();
        assert_height_data_for_trees(
            &tf,
            &connected_trees,
            &[
                (2.into(), &[m1_id, a1_id, b0_id]),
                (3.into(), &[m2_id, b1_id]),
                (4.into(), &[b2_id, c1_id]),
            ],
        );

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 1.into()).unwrap();
        assert_height_data_for_trees(
            &tf,
            &connected_trees,
            &[
                (1.into(), &[a0_id, m0_id]),
                (2.into(), &[m1_id, a1_id, b0_id]),
                (3.into(), &[m2_id, b1_id]),
                (4.into(), &[b2_id, c1_id]),
            ],
        );
    });
}

// Test connect_block_tree.
// The following block tree will be created:
// G----m0----m1----m2----m3
//      \-----b0----b1----b2
// Timestamp-wise, the tree will look as follows:
// ts0  ts1  ts2  ts3  ts4  ts5  ts6
// G----m0---m1---m2---m3
//      \--------------b0---b1---b2
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_block_tree2(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m2_id, result) = process_block(&mut tf, &m1_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (m3_id, result) = process_block(&mut tf, &m2_id.into(), &mut rng);
        assert!(result.is_ok());
        let (b0_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (b1_id, result) = process_block(&mut tf, &b0_id.into(), &mut rng);
        assert!(result.is_ok());

        tf.time_value.as_ref().unwrap().fetch_add(1);

        let (b2_id, result) = process_block(&mut tf, &b1_id.into(), &mut rng);
        assert!(result.is_ok());

        log::debug!("m0_id = {m0_id}, m1_id = {m1_id}, m2_id = {m2_id}, m3_id = {m3_id}, b0_id = {b0_id}, b1_id = {b1_id}, b2_id = {b2_id}");

        // Sanity check: ensure timestamps are as expected.
        let ts0 = tf.genesis().timestamp();
        let ts1 = tf.block_index(&m0_id).block_timestamp();
        let ts2 = tf.block_index(&m1_id).block_timestamp();
        let ts3 = tf.block_index(&m2_id).block_timestamp();
        let ts4 = tf.block_index(&m3_id).block_timestamp();
        assert_eq!(ts4, tf.block_index(&b0_id).block_timestamp());
        let ts5 = tf.block_index(&b1_id).block_timestamp();
        let ts6 = tf.block_index(&b2_id).block_timestamp();
        assert!(ts6 > ts5 && ts5 > ts4 && ts4 > ts3 && ts3 > ts2 && ts2 > ts1 && ts1 > ts0);

        //------------------------------------------------------------------------------------------

        // Start from the timestamp ts4.

        // The obtained trees will be as follows ('h' means height):
        // h2    h3    h4
        //             m3
        // b0----b1----b2

        let trees = tf
            .chainstate
            .get_block_tree_top_starting_from_timestamp(ts4, BlockValidity::Any)
            .unwrap();
        assert_height_data_for_trees(
            &tf,
            &trees,
            &[(2.into(), &[b0_id]), (3.into(), &[b1_id]), (4.into(), &[m3_id, b2_id])],
        );

        // With the minimum height of 3, try_connect_block_trees will try to extend the m chain adding m2 to it,
        // but then stop at height 3.
        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 3.into()).unwrap();
        assert_height_data_for_trees(
            &tf,
            &connected_trees,
            &[(2.into(), &[b0_id]), (3.into(), &[m2_id, b1_id]), (4.into(), &[m3_id, b2_id])],
        );

        // With the minimum height of 2, try_connect_block_trees will try to extend the m chain adding m2 and m1 to it,
        // but then stop at height 2.
        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 2.into()).unwrap();
        assert_height_data_for_trees(
            &tf,
            &connected_trees,
            &[
                (2.into(), &[m1_id, b0_id]),
                (3.into(), &[m2_id, b1_id]),
                (4.into(), &[m3_id, b2_id]),
            ],
        );

        let connected_trees =
            tf.chainstate.try_connect_block_trees(trees.clone(), 1.into()).unwrap();
        assert_height_data_for_trees(
            &tf,
            &connected_trees,
            &[
                (1.into(), &[m0_id]),
                (2.into(), &[m1_id, b0_id]),
                (3.into(), &[m2_id, b1_id]),
                (4.into(), &[m3_id, b2_id]),
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

fn check_trees_consistency(tf: &TestFramework, trees: &InMemoryBlockTrees) {
    let mut root_node_ids = BTreeSet::new();
    let mut block_ids_in_trees = Vec::new();

    for tree in trees.trees_iter() {
        check_tree_consistency(tree);

        let block_ids_in_tree = tree
            .all_block_indices_iter()
            .map(|idx| *idx.block_id())
            .collect::<BTreeSet<_>>();
        root_node_ids.insert(tree.root_node_id());
        block_ids_in_trees.push((tree.root_block_index().unwrap().clone(), block_ids_in_tree));
    }

    // All trees have distinct node ids.
    assert!(root_node_ids.len() == trees.roots_count());

    let mut iter1 = block_ids_in_trees.iter();
    while let Some((root_block_index1, block_ids_in_tree1)) = iter1.next() {
        for (root_block_index2, block_ids_in_tree2) in iter1.clone() {
            assert!(block_ids_in_tree1.is_disjoint(block_ids_in_tree2));

            if let Some(root_parent_id1) = root_block_index1
                .prev_block_id()
                .classify(tf.chainstate.get_chain_config())
                .chain_block_id()
            {
                assert!(block_ids_in_tree2.get(&root_parent_id1).is_none());
            }

            if let Some(root_parent_id2) = root_block_index2
                .prev_block_id()
                .classify(tf.chainstate.get_chain_config())
                .chain_block_id()
            {
                assert!(block_ids_in_tree1.get(&root_parent_id2).is_none());
            }
        }
    }
}

fn make_expected_data_map_by_height(
    expected_data: &[(BlockHeight, &[Id<Block>])],
) -> BTreeMap<BlockHeight, BTreeSet<Id<Block>>> {
    expected_data
        .iter()
        .map(|(height, ids)| (*height, ids.iter().copied().collect::<BTreeSet<_>>()))
        .collect()
}

fn assert_height_data_for_trees(
    tf: &TestFramework,
    actual_trees: &InMemoryBlockTrees,
    expected_data: &[(BlockHeight, &[Id<Block>])],
) {
    let expected_data = make_expected_data_map_by_height(expected_data);
    check_trees_consistency(tf, actual_trees);

    let actual = actual_trees.as_by_height_block_id_map().unwrap();

    assert_eq!(actual, expected_data);
}

fn assert_block_tree_top_by_height(
    tf: &TestFramework,
    start_from: BlockHeight,
    block_validity: BlockValidity,
    expected_data: &[(BlockHeight, &[Id<Block>])],
) {
    let actual_trees = tf
        .chainstate
        .get_block_tree_top_starting_from_height(start_from, block_validity)
        .unwrap();
    assert_height_data_for_trees(tf, &actual_trees, expected_data);
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
    check_trees_consistency(tf, &actual_trees);

    let actual = actual_trees.as_by_timestamp_block_id_map().unwrap();

    assert_eq!(actual, expected);
}

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

use chainstate_test_framework::TestFramework;
use common::primitives::Idable;
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_get_block_height_in_main_chain(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng).build();

    tf.create_chain(&tf.genesis().get_id().into(), 2, &mut rng).unwrap();
    tf.create_chain(&tf.genesis().get_id().into(), 1, &mut rng).unwrap();

    let block1_id = tf.index_at(1).block_id();
    let block1_height = tf.chainstate.get_block_height_in_main_chain(&(*block1_id).into()).unwrap();
    assert_eq!(block1_height, Some(1.into()));

    let block2_id = tf.index_at(2).block_id();
    let block2_height = tf.chainstate.get_block_height_in_main_chain(&(*block2_id).into()).unwrap();
    assert_eq!(block2_height, Some(2.into()));

    let block3_id = tf.index_at(3).block_id();
    let block3_height = tf.chainstate.get_block_height_in_main_chain(&(*block3_id).into()).unwrap();
    assert_eq!(block3_height, None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_is_block_in_main_chain(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng).build();

    tf.create_chain(&tf.genesis().get_id().into(), 2, &mut rng).unwrap();
    tf.create_chain(&tf.genesis().get_id().into(), 1, &mut rng).unwrap();

    let block1_id = tf.index_at(1).block_id();
    assert!(tf.chainstate.is_block_in_main_chain(&(*block1_id).into()).unwrap());

    let block2_id = tf.index_at(2).block_id();
    assert!(tf.chainstate.is_block_in_main_chain(&(*block2_id).into()).unwrap());

    let block3_id = tf.index_at(3).block_id();
    assert!(!tf.chainstate.is_block_in_main_chain(&(*block3_id).into()).unwrap());
}

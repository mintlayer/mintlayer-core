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

use rstest::rstest;

use super::helpers::{block_creation_helpers::*, block_status_helpers::*};
use chainstate::{BlockInvalidatorError, ChainstateError};
use chainstate_test_framework::TestFramework;
use chainstate_types::BlockValidationStage;
use common::{
    chain::{self, Block},
    primitives::{BlockDistance, Id, Idable},
};
use crypto::random::{CryptoRng, Rng};
use test_utils::random::{make_seedable_rng, Seed};

// Invalidate a0 in:
// /----a0----a1----a2
// G----m0----m1----m2----m3
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_stale_chain_invalidation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let m_tip_id = tf.create_chain(&genesis_id.into(), 4, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), m_tip_id);

        let (a0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());

        let (a1_id, result) = process_block(&mut tf, &a0_id.into(), &mut rng);
        assert!(result.is_ok());

        let (a2_id, result) = process_block(&mut tf, &a1_id.into(), &mut rng);
        assert!(result.is_ok());

        assert_ok_blocks_at_stage(
            &tf,
            &[a0_id, a1_id, a2_id],
            BlockValidationStage::CheckBlockOk,
        );

        tf.chainstate.invalidate_block(&a0_id).unwrap();

        assert_eq!(tf.best_block_id(), m_tip_id);
        assert_invalidated_blocks_at_stage(&tf, &[a0_id], BlockValidationStage::CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(
            &tf,
            &[a1_id, a2_id],
            BlockValidationStage::CheckBlockOk,
        );

        tf.chainstate.reset_block_failure_flags(&a0_id).unwrap();
        assert_ok_blocks_at_stage(
            &tf,
            &[a0_id, a1_id, a2_id],
            BlockValidationStage::CheckBlockOk,
        );
    });
}

// Invalidate m1 in:
// G----m0----m1
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_basic_tip_invalidation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());

        assert_eq!(tf.best_block_id(), m1_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id]);

        tf.chainstate.invalidate_block(&m1_id).unwrap();

        assert_eq!(tf.best_block_id(), m0_id);
        assert_fully_valid_blocks(&tf, &[m0_id]);
        assert_invalidated_blocks_at_stage(&tf, &[m1_id], BlockValidationStage::FullyChecked);

        tf.chainstate.reset_block_failure_flags(&m1_id).unwrap();
        assert_eq!(tf.best_block_id(), m1_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id]);
    });
}

// Invalidate m0 in:
// G----m0----m1
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_basic_parent_invalidation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());

        assert_eq!(tf.best_block_id(), m1_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id]);

        tf.chainstate.invalidate_block(&m0_id).unwrap();

        assert_eq!(tf.best_block_id(), genesis_id);
        assert_invalidated_blocks_at_stage(&tf, &[m0_id], BlockValidationStage::FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &[m1_id], BlockValidationStage::FullyChecked);

        tf.chainstate.reset_block_failure_flags(&m0_id).unwrap();
        assert_eq!(tf.best_block_id(), m1_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id]);
    });
}

// Here "m" represents the mainchain and other fields represent stale chains.
#[derive(Debug)]
struct TestChainBlockIds {
    m: Vec<Id<Block>>,
    a: Vec<Id<Block>>,
    b: Vec<Id<Block>>,
    c: Vec<Id<Block>>,
    d: Vec<Id<Block>>,
    e: Vec<Id<Block>>,
}

// Create the block tree for the complex_test below.
// Here "m" denotes the mainchain and other letters the stale chains; "!" denotes a block
// that is immediately determined to be invalid, and "?" denotes one that will be marked
// as invalid during a reorg; "(m1)" means that reorgs below m1 won't be allowed.
//      /------a0-----a1----a2----a3
//      |      /------b0---!b1---!b2
//      |      |------c0----c1---!c2
//      |      |------d0----d1----d2
//      |      |      /----?e0----e1----e2
// G----m0----(m1)----m2----m3----m4----m5----m6
fn make_complex_chain(rng: &mut (impl Rng + CryptoRng)) -> (TestFramework, TestChainBlockIds) {
    let mut tf = TestFramework::builder(rng)
        .with_chain_config(
            chain::config::create_unit_test_config_builder()
                .max_depth_for_reorg(BlockDistance::new(5))
                .build(),
        )
        .build();
    let genesis_id = tf.genesis().get_id();

    let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), rng);
    assert!(result.is_ok());
    let (m1_id, result) = process_block(&mut tf, &m0_id.into(), rng);
    assert!(result.is_ok());
    // The output #0 of this tx will transfer coins, and #1 will burn coins.
    let (m2_id, m3_tx_id, result) = process_block_split_parent_reward(&mut tf, &m1_id.into(), rng);
    assert!(result.is_ok());
    let (m3_id, result) = process_block_spend_tx(&mut tf, &m2_id.into(), &m3_tx_id, 0, rng);
    assert!(result.is_ok());

    let (a0_id, result) = process_block(&mut tf, &m0_id.into(), rng);
    assert!(result.is_ok());
    let (a1_id, result) = process_block(&mut tf, &a0_id.into(), rng);
    assert!(result.is_ok());

    let (m4_id, result) = process_block(&mut tf, &m3_id.into(), rng);
    assert!(result.is_ok());

    let (b0_id, result) = process_block(&mut tf, &m1_id.into(), rng);
    assert!(result.is_ok());
    let (b1_id, result) = process_block_with_empty_tx(&mut tf, &b0_id.into());
    assert!(result.is_err());
    let (b2_id, result) = process_block_with_empty_tx(&mut tf, &b1_id.into());
    assert!(result.is_err());

    let (c0_id, result) = process_block(&mut tf, &m1_id.into(), rng);
    assert!(result.is_ok());
    let (c1_id, result) = process_block(&mut tf, &c0_id.into(), rng);
    assert!(result.is_ok());
    let (c2_id, result) = process_block_with_empty_tx(&mut tf, &c1_id.into());
    assert!(result.is_err());

    let (m5_id, result) = process_block(&mut tf, &m4_id.into(), rng);
    assert!(result.is_ok());

    let (a2_id, result) = process_block(&mut tf, &a1_id.into(), rng);
    assert!(result.is_ok());
    let (a3_id, result) = process_block(&mut tf, &a2_id.into(), rng);
    assert!(result.is_ok());

    let (d0_id, result) = process_block(&mut tf, &m1_id.into(), rng);
    assert!(result.is_ok());
    let (d1_id, result) = process_block(&mut tf, &d0_id.into(), rng);
    assert!(result.is_ok());
    let (d2_id, result) = process_block(&mut tf, &d1_id.into(), rng);
    assert!(result.is_ok());

    let (m6_id, result) = process_block(&mut tf, &m5_id.into(), rng);
    assert!(result.is_ok());

    // Try to spend burnt coins
    let (e0_id, result) = process_block_spend_tx(&mut tf, &m2_id.into(), &m3_tx_id, 1, rng);
    assert!(result.is_ok());
    let (e1_id, result) = process_block(&mut tf, &e0_id.into(), rng);
    assert!(result.is_ok());
    let (e2_id, result) = process_block(&mut tf, &e1_id.into(), rng);
    assert!(result.is_ok());

    assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());

    let m = vec![m0_id, m1_id, m2_id, m3_id, m4_id, m5_id, m6_id];
    let a = vec![a0_id, a1_id, a2_id, a3_id];
    let b = vec![b0_id, b1_id, b2_id];
    let c = vec![c0_id, c1_id, c2_id];
    let d = vec![d0_id, d1_id, d2_id];
    let e = vec![e0_id, e1_id, e2_id];

    // Perform some sanity checks
    assert_in_main_chain(&tf, &m);
    assert_fully_valid_blocks(&tf, &m);
    assert_eq!(tf.best_block_id(), m[6]);

    assert_in_stale_chain(&tf, &a);
    assert_ok_blocks_at_stage(&tf, &a, BlockValidationStage::CheckBlockOk);

    assert_in_stale_chain(&tf, &b);
    assert_ok_blocks_at_stage(&tf, &b[..1], BlockValidationStage::CheckBlockOk);
    assert_bad_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

    assert_in_stale_chain(&tf, &c);
    assert_ok_blocks_at_stage(&tf, &c[..2], BlockValidationStage::CheckBlockOk);
    assert_bad_blocks_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

    assert_in_stale_chain(&tf, &d);
    assert_ok_blocks_at_stage(&tf, &d, BlockValidationStage::CheckBlockOk);

    assert_in_stale_chain(&tf, &e);
    assert_ok_blocks_at_stage(&tf, &e, BlockValidationStage::CheckBlockOk);

    (tf, TestChainBlockIds { m, a, b, c, d, e })
}

// Here block_ids come from make_complex_chain.
fn complex_test_impl(mut tf: TestFramework, block_ids: &TestChainBlockIds) {
    use BlockValidationStage::*;

    let TestChainBlockIds { m, a, b, c, d, e } = block_ids;

    {
        // Step 1 - invalidate m3.
        // This should first try to switch to the "e" chain, whose activation should fail,
        // and then the "d" chain should be activated instead.
        tf.chainstate.invalidate_block(&m[3]).unwrap();

        // m3 and later blocks are now invalid; m2 is stale.
        assert_in_stale_chain(&tf, &m[2..]);
        assert_in_main_chain(&tf, &m[..2]);
        assert_invalidated_blocks_at_stage(&tf, &m[3..4], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &m[4..], FullyChecked);

        // "d" is now the mainchain
        assert_in_main_chain(&tf, d);
        assert_fully_valid_blocks(&tf, d);
        assert_eq!(tf.best_block_id(), d[2]);

        // "e" chain is now also invalid due to a failed reorg.
        assert_in_stale_chain(&tf, &e[0..]);
        assert_bad_blocks_at_stage(&tf, &e[..1], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &e[1..], CheckBlockOk);

        // "a", "b", "c" are the same as before
        assert_in_stale_chain(&tf, a);
        assert_ok_blocks_at_stage(&tf, a, BlockValidationStage::CheckBlockOk);

        assert_in_stale_chain(&tf, b);
        assert_ok_blocks_at_stage(&tf, &b[..1], BlockValidationStage::CheckBlockOk);
        assert_bad_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, c);
        assert_ok_blocks_at_stage(&tf, &c[..2], BlockValidationStage::CheckBlockOk);
        assert_bad_blocks_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

        // Check the min height for reorg and the best chain candidates.
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
    }

    {
        // Step 2 - invalidate m2.
        // All descendants of m2 are already invalid, but not all of them have
        // the "invalid parent" flag. Now they all should get one.
        tf.chainstate.invalidate_block(&m[2]).unwrap();

        assert_in_stale_chain(&tf, &m[2..]);
        assert_in_main_chain(&tf, &m[..2]);
        assert_invalidated_blocks_at_stage(&tf, &m[2..3], FullyChecked);
        assert_invalidated_blocks_with_bad_parent_at_stage(&tf, &m[3..4], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &m[4..], FullyChecked);

        assert_in_stale_chain(&tf, &e[0..]);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &e[..1], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &e[1..], CheckBlockOk);

        // "a", "b", "c", "d" are the same as before
        assert_in_stale_chain(&tf, a);
        assert_ok_blocks_at_stage(&tf, a, BlockValidationStage::CheckBlockOk);

        assert_in_stale_chain(&tf, b);
        assert_ok_blocks_at_stage(&tf, &b[..1], BlockValidationStage::CheckBlockOk);
        assert_bad_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, c);
        assert_ok_blocks_at_stage(&tf, &c[..2], BlockValidationStage::CheckBlockOk);
        assert_bad_blocks_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

        assert_in_main_chain(&tf, d);
        assert_fully_valid_blocks(&tf, d);
        assert_eq!(tf.best_block_id(), d[2]);

        // Check the min height for reorg and the best chain candidates.
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
    }

    {
        // Step 3 - invalidate the "d" branch.
        tf.chainstate.invalidate_block(&d[0]).unwrap();

        // c0, c1 is now the mainchain; c2 is still bad.
        assert_in_main_chain(&tf, &c[..2]);
        assert_in_stale_chain(&tf, &c[2..]);
        assert_fully_valid_blocks(&tf, &c[..2]);
        assert_bad_blocks_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

        // "d" is now invalid
        assert_in_stale_chain(&tf, d);
        assert_invalidated_blocks_at_stage(&tf, &d[..1], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &d[1..], FullyChecked);

        // "a", "b", "e", "m" haven't changed.
        assert_in_stale_chain(&tf, a);
        assert_ok_blocks_at_stage(&tf, a, BlockValidationStage::CheckBlockOk);

        assert_in_stale_chain(&tf, b);
        assert_ok_blocks_at_stage(&tf, &b[..1], BlockValidationStage::CheckBlockOk);
        assert_bad_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, &e[0..]);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &e[0..1], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &e[1..], CheckBlockOk);

        assert_in_stale_chain(&tf, &m[2..]);
        assert_in_main_chain(&tf, &m[..2]);
        assert_invalidated_blocks_at_stage(&tf, &m[2..3], FullyChecked);
        assert_invalidated_blocks_with_bad_parent_at_stage(&tf, &m[3..4], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &m[4..], FullyChecked);

        // Check the min height for reorg and the best chain candidates.
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
    }

    {
        // Step 4 - invalidate the "c" branch.
        tf.chainstate.invalidate_block(&c[0]).unwrap();

        // b0 is now on the mainchain, b1 and b2 are still bad
        assert_in_main_chain(&tf, &b[..1]);
        assert_in_stale_chain(&tf, &b[1..]);
        assert_fully_valid_blocks(&tf, &b[..1]);
        assert_bad_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

        // The entire "c" is now invalid
        assert_in_stale_chain(&tf, c);
        assert_invalidated_blocks_at_stage(&tf, &c[..1], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &c[1..2], FullyChecked);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

        // "a", "d", "e", "m" haven't changed.
        assert_in_stale_chain(&tf, a);
        assert_ok_blocks_at_stage(&tf, a, BlockValidationStage::CheckBlockOk);

        assert_in_stale_chain(&tf, d);
        assert_invalidated_blocks_at_stage(&tf, &d[..1], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &d[1..], FullyChecked);

        assert_in_stale_chain(&tf, &e[0..]);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &e[0..1], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &e[1..], CheckBlockOk);

        assert_in_stale_chain(&tf, &m[2..]);
        assert_in_main_chain(&tf, &m[..2]);
        assert_invalidated_blocks_at_stage(&tf, &m[2..3], FullyChecked);
        assert_invalidated_blocks_with_bad_parent_at_stage(&tf, &m[3..4], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &m[4..], FullyChecked);

        // Check the min height for reorg and the best chain candidates.
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
    }

    {
        // Step 5 - try invalidate m1.
        // This should be impossible, because it'd require a reorg to blocks below the allowed
        // reorg depth.
        let err = tf.chainstate.invalidate_block(&m[1]).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::BlockInvalidatorError(
                BlockInvalidatorError::BlockTooDeepToInvalidate(m[1])
            )
        );

        // Nothing has changed.
        assert_in_stale_chain(&tf, a);
        assert_ok_blocks_at_stage(&tf, a, BlockValidationStage::CheckBlockOk);

        assert_in_main_chain(&tf, &b[..1]);
        assert_in_stale_chain(&tf, &b[1..]);
        assert_fully_valid_blocks(&tf, &b[..1]);
        assert_bad_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, c);
        assert_invalidated_blocks_at_stage(&tf, &c[..1], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &c[1..2], FullyChecked);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, d);
        assert_invalidated_blocks_at_stage(&tf, &d[..1], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &d[1..], FullyChecked);

        assert_in_stale_chain(&tf, &e[0..]);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &e[0..1], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &e[1..], CheckBlockOk);

        assert_in_stale_chain(&tf, &m[2..]);
        assert_in_main_chain(&tf, &m[..2]);
        assert_invalidated_blocks_at_stage(&tf, &m[2..3], FullyChecked);
        assert_invalidated_blocks_with_bad_parent_at_stage(&tf, &m[3..4], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &m[4..], FullyChecked);

        // Check the min height for reorg and the best chain candidates.
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
    }

    {
        // Step 6 - invalidate a2.
        // (Though it's a chain that starts below the reorg limit, there is nothing wrong with
        // trying to invalidate it.)
        tf.chainstate.invalidate_block(&a[2]).unwrap();

        // The statuses on "a" have been changed accordingly.
        assert_in_stale_chain(&tf, a);
        assert_ok_blocks_at_stage(&tf, &a[..2], BlockValidationStage::CheckBlockOk);
        assert_invalidated_blocks_at_stage(&tf, &a[2..3], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &a[3..], CheckBlockOk);

        // Nothing else has changed.
        assert_in_main_chain(&tf, &b[..1]);
        assert_in_stale_chain(&tf, &b[1..]);
        assert_fully_valid_blocks(&tf, &b[..1]);
        assert_bad_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, c);
        assert_invalidated_blocks_at_stage(&tf, &c[..1], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &c[1..2], FullyChecked);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, d);
        assert_invalidated_blocks_at_stage(&tf, &d[..1], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &d[1..], FullyChecked);

        assert_in_stale_chain(&tf, &e[0..]);
        assert_bad_blocks_with_bad_parent_at_stage(&tf, &e[0..1], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &e[1..], CheckBlockOk);

        assert_in_stale_chain(&tf, &m[2..]);
        assert_in_main_chain(&tf, &m[..2]);
        assert_invalidated_blocks_at_stage(&tf, &m[2..3], FullyChecked);
        assert_invalidated_blocks_with_bad_parent_at_stage(&tf, &m[3..4], FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &m[4..], FullyChecked);

        // Check the min height for reorg and the best chain candidates.
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
    }

    {
        // Step 7 - reload the chainstate. Check that the min height for reorg is still the same.
        tf = tf.reload();
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
    }

    {
        // Step 8 - reset the fail flags of m1 and its descendants.
        // Note that m1 itself hasn't been invalidated, but this should not be a problem.
        tf.chainstate.reset_block_failure_flags(&m[1]).unwrap();

        // The "a" chain is still the same.
        assert_in_stale_chain(&tf, a);
        assert_ok_blocks_at_stage(&tf, &a[..2], BlockValidationStage::CheckBlockOk);
        assert_invalidated_blocks_at_stage(&tf, &a[2..3], CheckBlockOk);
        assert_blocks_with_bad_parent_at_stage(&tf, &a[3..], CheckBlockOk);

        // "m" has been reverted to the initial condition.
        assert_in_main_chain(&tf, m);
        assert_fully_valid_blocks(&tf, m);
        assert_eq!(tf.best_block_id(), m[6]);

        // "b", "c" and "d" are different - fully validated blocks have retained their FullyChecked
        // status; and the blocks that were initially invalid have become "ok/Unchecked".
        assert_in_stale_chain(&tf, b);
        assert_fully_valid_blocks(&tf, &b[..1]);
        assert_ok_blocks_at_stage(&tf, &b[1..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, c);
        assert_fully_valid_blocks(&tf, &c[..2]);
        assert_ok_blocks_at_stage(&tf, &c[2..], BlockValidationStage::Unchecked);

        assert_in_stale_chain(&tf, d);
        assert_fully_valid_blocks(&tf, d);

        // "e" has been reverted to the initial state.
        assert_in_stale_chain(&tf, e);
        assert_ok_blocks_at_stage(&tf, e, BlockValidationStage::CheckBlockOk);

        // Check the min height for reorg and the best chain candidates.
        assert_eq!(tf.get_min_height_with_allowed_reorg(), 2.into());
        // Note that now b2 and c2 are among the candidates instead of b0 and c1.
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn complex_test_normal(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (tf, block_ids) = make_complex_chain(&mut rng);

        complex_test_impl(tf, &block_ids);
    });
}

// Note: this test is an artifact of an earlier implementation, where best_chain_candidates
// was a member of chainstate, which was updated on the fly; so, there could be a difference
// between chainstate built step by step and one initialized with an already non-empty storage.
// But it doesn't hurt to continue checking this scenario, just in case.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn complex_test_after_reload(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (tf, block_ids) = make_complex_chain(&mut rng);

        complex_test_impl(tf.reload(), &block_ids);
    });
}

// Invalidate m1 in:
// /----a0
// G----m0----m1
// where a0 and m0 have the same chain trust. The reorg should not occur.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_tip_invalidation_with_no_better_candidates(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());

        let (a0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());

        assert_eq!(tf.best_block_id(), m1_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id]);
        assert_ok_blocks_at_stage(&tf, &[a0_id], BlockValidationStage::CheckBlockOk);

        assert_eq!(
            tf.block_index((&a0_id).into()).chain_trust(),
            tf.block_index((&m0_id).into()).chain_trust()
        );

        tf.chainstate.invalidate_block(&m1_id).unwrap();

        assert_eq!(tf.best_block_id(), m0_id);
        assert_fully_valid_blocks(&tf, &[m0_id]);
        assert_invalidated_blocks_at_stage(&tf, &[m1_id], BlockValidationStage::FullyChecked);
        assert_ok_blocks_at_stage(&tf, &[a0_id], BlockValidationStage::CheckBlockOk);

        tf.chainstate.reset_block_failure_flags(&m1_id).unwrap();

        assert_eq!(tf.best_block_id(), m1_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id]);
        assert_ok_blocks_at_stage(&tf, &[a0_id], BlockValidationStage::CheckBlockOk);
    });
}

// Invalidate m0 in:
// /----a0---!a1
// G----m0----m1
// where a1 is completely invalid (i.e. it didn't pass even the check_block stage), but its
// status has been manually reset to "ok".
// This checks two facts:
// 1) It's ok to try to reorg to blocks like that (i.e. it'll fail gracefully);
// 2) If a reorg to the tip of a branch fails, its parents from the same branch are still
// considered for the next attempt.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_invalidation_with_reorg_to_chain_with_bad_tip(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());

        let (a0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (a1_id, result) = process_block_with_empty_tx(&mut tf, &a0_id.into());
        assert!(result.is_err());

        // Reset the fail flags of a1 to get to the desired state of the chain.
        tf.chainstate.reset_block_failure_flags(&a1_id).unwrap();

        assert_eq!(tf.best_block_id(), m1_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id]);
        assert_ok_blocks_at_stage(&tf, &[a0_id], BlockValidationStage::CheckBlockOk);
        assert_ok_blocks_at_stage(&tf, &[a1_id], BlockValidationStage::Unchecked);

        tf.chainstate.invalidate_block(&m0_id).unwrap();

        // a0 is now the best block, a1 is back to its "bad" status.
        assert_eq!(tf.best_block_id(), a0_id);
        assert_bad_blocks_at_stage(&tf, &[a1_id], BlockValidationStage::Unchecked);
        assert_fully_valid_blocks(&tf, &[a0_id]);
        assert_invalidated_blocks_at_stage(&tf, &[m0_id], BlockValidationStage::FullyChecked);
        assert_blocks_with_bad_parent_at_stage(&tf, &[m1_id], BlockValidationStage::FullyChecked);
    });
}

// Add 2 new blocks on top of a1 in:
// /----a0---!a1
// G----m0----m1----m2
// where a1 is completely invalid (i.e. it didn't pass even the check_block stage), but its
// status has been manually reset to "ok".
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_add_block_to_chain_with_bad_tip(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (m0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (m1_id, result) = process_block(&mut tf, &m0_id.into(), &mut rng);
        assert!(result.is_ok());
        let (m2_id, result) = process_block(&mut tf, &m1_id.into(), &mut rng);
        assert!(result.is_ok());

        let (a0_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.is_ok());
        let (a1_id, result) = process_block_with_empty_tx(&mut tf, &a0_id.into());
        assert!(result.is_err());

        // Reset the fail flags of a1 to get to the desired state of the chain.
        tf.chainstate.reset_block_failure_flags(&a1_id).unwrap();

        assert_eq!(tf.best_block_id(), m2_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id, m2_id]);
        assert_ok_blocks_at_stage(&tf, &[a0_id], BlockValidationStage::CheckBlockOk);
        assert_ok_blocks_at_stage(&tf, &[a1_id], BlockValidationStage::Unchecked);

        let (a2_id, result) = process_block_spend_parent_reward(&mut tf, &a1_id.into(), &mut rng);
        assert!(result.is_ok());

        // a2 has been added successfully to the stale chain; everything else is the same.
        assert_eq!(tf.best_block_id(), m2_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id, m2_id]);
        assert_ok_blocks_at_stage(&tf, &[a0_id, a2_id], BlockValidationStage::CheckBlockOk);
        assert_ok_blocks_at_stage(&tf, &[a1_id], BlockValidationStage::Unchecked);

        let (a3_id, result) = process_block(&mut tf, &a2_id.into(), &mut rng);
        assert!(result.is_err());

        // A reorg has been triggered, which has failed.
        // "m" is still the best chain; a1 has been marked as invalid, a2 and a3 have been marked
        // as having an invalid parent.
        assert_eq!(tf.best_block_id(), m2_id);
        assert_fully_valid_blocks(&tf, &[m0_id, m1_id, m2_id]);
        assert_ok_blocks_at_stage(&tf, &[a0_id], BlockValidationStage::CheckBlockOk);
        assert_bad_blocks_at_stage(&tf, &[a1_id], BlockValidationStage::Unchecked);
        assert_blocks_with_bad_parent_at_stage(
            &tf,
            &[a2_id, a3_id],
            BlockValidationStage::CheckBlockOk,
        );
    });
}

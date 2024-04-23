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
use chainstate::{BlockError, BlockSource, ChainstateError, CheckBlockError};
use chainstate_test_framework::TestFramework;
use chainstate_types::BlockValidationStage;
use common::primitives::Idable;
use test_utils::random::{make_seedable_rng, Seed};

// Check processing of a good block.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_process_good_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (block_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        let block_index_returned = result.unwrap();

        // The first block will trigger a trivial reorg, because of which "process_block" will
        // return a BlockIndex. We need to check that it has the correct status too.
        assert!(block_index_returned.is_some());
        assert_fully_valid_block(block_index_returned.unwrap().status());

        // Now check the status that is stored in the DB.
        let block_status = get_block_status(&tf, &block_id);
        assert_fully_valid_block(block_status);
    });
}

// Process a bunch of good blocks on a side-chain and then extend it to trigger a reorg.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_process_good_block_with_later_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        tf.create_chain(&genesis_id.into(), 3, &mut rng).unwrap();

        let (block1_id, result) = process_block(&mut tf, &genesis_id.into(), &mut rng);
        assert!(result.unwrap().is_none());
        let block1_status = get_block_status(&tf, &block1_id);
        assert_ok_block_at_stage(block1_status, BlockValidationStage::CheckBlockOk);

        let (block2_id, result) = process_block(&mut tf, &block1_id.into(), &mut rng);
        assert!(result.unwrap().is_none());
        let block2_status = get_block_status(&tf, &block2_id);
        assert_ok_block_at_stage(block2_status, BlockValidationStage::CheckBlockOk);

        // Block3 branches off from block1 too.
        let (block3_id, result) = process_block(&mut tf, &block1_id.into(), &mut rng);
        assert!(result.unwrap().is_none());
        let block3_status = get_block_status(&tf, &block3_id);
        assert_ok_block_at_stage(block3_status, BlockValidationStage::CheckBlockOk);

        assert!(!tf.is_block_in_main_chain(&block1_id));
        assert!(!tf.is_block_in_main_chain(&block2_id));
        assert!(!tf.is_block_in_main_chain(&block3_id));

        // This will trigger a reorg.
        tf.create_chain(&block2_id.into(), 2, &mut rng).unwrap();

        // Blocks 1 & 2 now must be fully valid and on the main-chain.
        assert!(tf.is_block_in_main_chain(&block1_id));
        let block1_status = get_block_status(&tf, &block1_id);
        assert_fully_valid_block(block1_status);

        assert!(tf.is_block_in_main_chain(&block2_id));
        let block2_status = get_block_status(&tf, &block2_id);
        assert_fully_valid_block(block2_status);

        // Nothing has changed for block3 though.
        assert!(!tf.is_block_in_main_chain(&block3_id));
        let block3_status = get_block_status(&tf, &block3_id);
        assert_ok_block_at_stage(block3_status, BlockValidationStage::CheckBlockOk);
    });
}

// Basic process_block failure.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_process_block_failure(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (bad_block_id, result) =
            process_block_with_empty_tx(&mut rng, &mut tf, &genesis_id.into());
        // processing should have failed, but we don't care about the exact error.
        result.unwrap_err();

        let block_status = get_block_status(&tf, &bad_block_id);
        assert_bad_block_at_stage(block_status, BlockValidationStage::Unchecked);
    });
}

// Check a process_block failure due to a bad parent.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_process_block_with_bad_parent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (bad_block_id, result) =
            process_block_with_empty_tx(&mut rng, &mut tf, &genesis_id.into());
        // processing should have failed, but we don't care about the exact error.
        result.unwrap_err();

        let bad_block_status = get_block_status(&tf, &bad_block_id);
        assert!(!bad_block_status.is_ok());

        // Now create a good block, but using bad_block as the parent.
        let (block_id, result) =
            process_block_spend_parent_reward(&mut tf, &bad_block_id.into(), &mut rng);
        let error = result.unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidParent {
                    block_id,
                    parent_block_id: bad_block_id.into()
                }
            ))
        );

        let block_status = get_block_status(&tf, &block_id);
        assert_bad_block_at_stage(block_status, BlockValidationStage::Unchecked);
    });
}

// Check a preliminary_headers_check failure due to a bad parent.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_preliminary_headers_check_with_bad_parent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (bad_block_id, result) =
            process_block_with_empty_tx(&mut rng, &mut tf, &genesis_id.into());
        // processing should have failed, but we don't care about the exact error.
        result.unwrap_err();

        let bad_block_status = get_block_status(&tf, &bad_block_id);
        assert!(!bad_block_status.is_ok());

        // Now create a good block, but using bad_block as the parent.
        let (block, _) = build_block_spend_parent_reward(&mut tf, &bad_block_id.into(), &mut rng);

        let error = tf
            .chainstate
            .preliminary_headers_check(std::slice::from_ref(block.header()))
            .unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidParent {
                    block_id: block.get_id(),
                    parent_block_id: bad_block_id.into()
                }
            ))
        );
    });
}

// Check a process_block failure during the final (i.e. "activate_best_chain") stage.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_process_block_final_stage_failure(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        // In the first block, create a tx that burns some coins.
        let (block1, tx1) = build_block_burn_parent_reward(&mut tf, &genesis_id.into(), &mut rng);
        let block1_id = block1.get_id();
        tf.process_block(block1, BlockSource::Local).unwrap();

        let block1_status = get_block_status(&tf, &block1_id);
        assert_fully_valid_block(block1_status);

        // In the second block, create a tx that tries to spend burnt coins.
        let (block2_id, result) = process_block_spend_tx(
            &mut tf,
            &block1_id.into(),
            &tx1.transaction().get_id(),
            0,
            &mut rng,
        );
        // Processing should have failed, but we don't care about the exact error.
        assert!(result.is_err());

        let block2_status = get_block_status(&tf, &block2_id);
        assert_bad_block_at_stage(block2_status, BlockValidationStage::CheckBlockOk);
    });
}

// Same as above, but here the bad block is created on a side-chain and then a reorg
// to that chain is triggered.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_process_block_final_stage_delayed_failure(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        tf.create_chain(&genesis_id.into(), 4, &mut rng).unwrap();

        // In the first block, create a tx that burns some coins.
        let (block1, tx1) = build_block_burn_parent_reward(&mut tf, &genesis_id.into(), &mut rng);
        let block1_id = block1.get_id();
        tf.process_block(block1, BlockSource::Local).unwrap();

        // In the second block, create a tx that tries to spend burnt coins.
        let (block2_id, result) = process_block_spend_tx(
            &mut tf,
            &block1_id.into(),
            &tx1.transaction().get_id(),
            0,
            &mut rng,
        );
        assert!(result.unwrap().is_none());

        // On top of block 2 create a subtree of good blocks.

        let (block3_id, result) = process_block(&mut tf, &block2_id.into(), &mut rng);
        assert!(result.unwrap().is_none());

        let (block4_id, result) = process_block(&mut tf, &block3_id.into(), &mut rng);
        assert!(result.unwrap().is_none());

        // Note: using block3 as the parent is intended.
        let (block5_id, result) = process_block(&mut tf, &block3_id.into(), &mut rng);
        assert!(result.unwrap().is_none());

        // No reorg has occurred yet.
        assert_ok_blocks_at_stage(
            &tf,
            &[block1_id, block2_id, block3_id, block4_id, block5_id],
            BlockValidationStage::CheckBlockOk,
        );
        assert_in_stale_chain(
            &tf,
            &[block1_id, block2_id, block3_id, block4_id, block5_id],
        );

        // This will trigger a reorg that should fail.
        let (block6_id, result) = process_block(&mut tf, &block4_id.into(), &mut rng);
        assert!(result.is_err());

        // Block1 is still not on the mainchain, because the reorg wasn't successful.
        assert!(!tf.is_block_in_main_chain(&block1_id));
        // And it still has the CheckBlockOk status even though it should have been successfully
        // validated, because successful validations that occur during a failed reorg are
        // currently not recorded.
        assert_ok_blocks_at_stage(&tf, &[block1_id], BlockValidationStage::CheckBlockOk);

        // Block2 is now marked as invalid.
        assert_bad_blocks_at_stage(&tf, &[block2_id], BlockValidationStage::CheckBlockOk);

        // Blocks 3-6 are also marked as invalid, but for a different reason - one of
        // their ancestors is invalid.
        assert_blocks_with_bad_parent_at_stage(
            &tf,
            &[block3_id, block4_id, block5_id, block6_id],
            BlockValidationStage::CheckBlockOk,
        );
    });
}

// Check orphans cleanup after a process_block failure.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_orphans_cleanup_on_process_block_failure(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        // In the first block, create a tx that burns some coins.
        let (base_block, tx1) =
            build_block_burn_parent_reward(&mut tf, &genesis_id.into(), &mut rng);
        let base_block_id = base_block.get_id();
        tf.process_block(base_block, BlockSource::Local).unwrap();
        let base_block_status = get_block_status(&tf, &base_block_id);
        assert_fully_valid_block(base_block_status);

        // Create a bad block that tries to spend burnt coins, but don't process it yet.
        let bad_block = build_block_spend_tx(
            &mut tf,
            &base_block_id.into(),
            &tx1.transaction().get_id(),
            0,
            &mut rng,
        );
        let bad_block_id = bad_block.get_id();

        let (orphan1_id, result) =
            process_block_spend_parent_reward(&mut tf, &bad_block_id.into(), &mut rng);
        assert_orphan_added_result(result);

        let (orphan2_id, result) =
            process_block_spend_parent_reward(&mut tf, &bad_block_id.into(), &mut rng);
        assert_orphan_added_result(result);

        let (orphan3_id, result) =
            process_block_spend_parent_reward(&mut tf, &orphan2_id.into(), &mut rng);
        assert_orphan_added_result(result);

        let another_missing_parent = build_block(&mut tf, &genesis_id.into(), &mut rng);

        let (unrelated_orphan_id, result) = process_block_spend_parent_reward(
            &mut tf,
            &another_missing_parent.get_id().into(),
            &mut rng,
        );
        assert_orphan_added_result(result);

        // Assert that all of them are orphans.
        assert!(tf.chainstate.is_already_an_orphan(&orphan1_id));
        assert!(tf.chainstate.is_already_an_orphan(&orphan2_id));
        assert!(tf.chainstate.is_already_an_orphan(&orphan3_id));
        assert!(tf.chainstate.is_already_an_orphan(&unrelated_orphan_id));

        // And they are not in the DB.
        assert_block_data_exists(&tf, &orphan1_id, false);
        assert_block_data_exists(&tf, &orphan2_id, false);
        assert_block_data_exists(&tf, &orphan3_id, false);
        assert_block_data_exists(&tf, &unrelated_orphan_id, false);

        // Process the bad block.
        tf.process_block(bad_block, BlockSource::Local).unwrap_err();

        // Assert that only unrelated_orphan remains.
        assert!(!tf.chainstate.is_already_an_orphan(&orphan1_id));
        assert!(!tf.chainstate.is_already_an_orphan(&orphan2_id));
        assert!(!tf.chainstate.is_already_an_orphan(&orphan3_id));
        assert!(tf.chainstate.is_already_an_orphan(&unrelated_orphan_id));

        // And they still are not in the DB.
        assert_block_data_exists(&tf, &orphan1_id, false);
        assert_block_data_exists(&tf, &orphan2_id, false);
        assert_block_data_exists(&tf, &orphan3_id, false);
        assert_block_data_exists(&tf, &unrelated_orphan_id, false);
    });
}

// Check processing of a good block twice.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_good_block_processed_again(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let block = build_block(&mut tf, &genesis_id.into(), &mut rng);
        let block_id = block.get_id();
        tf.process_block(block.clone(), BlockSource::Local).unwrap().unwrap();

        let block_status = get_block_status(&tf, &block_id);
        assert_fully_valid_block(block_status);

        // Process it again.
        let error = tf.process_block(block, BlockSource::Local).unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::BlockAlreadyProcessed(block_id))
        );
    });
}

// Check a failure when processing the same bad block twice.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_bad_block_processed_again(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let bad_block = build_block_with_empty_tx(&mut rng, &mut tf, &genesis_id.into());
        let bad_block_id = bad_block.get_id();
        // processing should fail, but we don't care about the exact error.
        tf.process_block(bad_block.clone(), BlockSource::Local).unwrap_err();

        let bad_block_status = get_block_status(&tf, &bad_block_id);
        assert!(!bad_block_status.is_ok());

        // Process it again
        let error = tf.process_block(bad_block, BlockSource::Local).unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::InvalidBlockAlreadyProcessed(
                bad_block_id
            ))
        );
    });
}

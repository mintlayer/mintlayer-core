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

use chainstate::{
    BlockError, BlockIndex, BlockSource, ChainstateError, CheckBlockError, OrphanCheckError,
};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use chainstate_types::{BlockStatus, BlockValidationStage};
use common::{
    chain::{
        output_value::OutputValue, signed_transaction::SignedTransaction, Block, GenBlock,
        OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

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

        let (bad_block_id, result) = process_block_with_empty_tx(&mut tf, &genesis_id.into());
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

        let (bad_block_id, result) = process_block_with_empty_tx(&mut tf, &genesis_id.into());
        // processing should have failed, but we don't care about the exact error.
        result.unwrap_err();

        let bad_block_status = get_block_status(&tf, &bad_block_id);
        assert_bad_block(bad_block_status);

        // Now create a good block, but using bad_block as the parent.
        let (block_id, result) =
            process_block_spend_parent_reward(&mut tf, &bad_block_id.into(), &mut rng);
        let error = result.unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidParent(block_id)
            ))
        );

        let block_status = get_block_status(&tf, &block_id);
        assert_bad_block_at_stage(block_status, BlockValidationStage::Unchecked);
    });
}

// Check a preliminary_header_check failure due to a bad parent.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_preliminary_header_check_with_bad_parent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let (bad_block_id, result) = process_block_with_empty_tx(&mut tf, &genesis_id.into());
        // processing should have failed, but we don't care about the exact error.
        result.unwrap_err();

        let bad_block_status = get_block_status(&tf, &bad_block_id);
        assert_bad_block(bad_block_status);

        // Now create a good block, but using bad_block as the parent.
        let (block, _) = build_block_spend_parent_reward(&mut tf, &bad_block_id.into(), &mut rng);

        let error = tf.chainstate.preliminary_header_check(block.header().clone()).unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidParent(block.get_id())
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

        let block1_status = get_block_status(&tf, &block1_id);
        assert_ok_block_at_stage(block1_status, BlockValidationStage::CheckBlockOk);

        // In the second block, create a tx that tries to spend burnt coins.
        let (block2_id, result) = process_block_spend_tx(
            &mut tf,
            &block1_id.into(),
            &tx1.transaction().get_id(),
            &mut rng,
        );
        assert!(result.unwrap().is_none());
        let block2_status = get_block_status(&tf, &block2_id);
        assert_ok_block_at_stage(block2_status, BlockValidationStage::CheckBlockOk);

        // On top of block 2 create a subtree of good blocks.

        let (block3_id, result) = process_block(&mut tf, &block2_id.into(), &mut rng);
        assert!(result.unwrap().is_none());
        let block3_status = get_block_status(&tf, &block3_id);
        assert_ok_block_at_stage(block3_status, BlockValidationStage::CheckBlockOk);

        let (block4_id, result) = process_block(&mut tf, &block3_id.into(), &mut rng);
        assert!(result.unwrap().is_none());
        let block4_status = get_block_status(&tf, &block4_id);
        assert_ok_block_at_stage(block4_status, BlockValidationStage::CheckBlockOk);

        // Note: using block3 as the parent is intended.
        let (block5_id, result) = process_block(&mut tf, &block3_id.into(), &mut rng);
        assert!(result.unwrap().is_none());
        let block5_status = get_block_status(&tf, &block5_id);
        assert_ok_block_at_stage(block5_status, BlockValidationStage::CheckBlockOk);

        // No reorg has occurred yet.
        assert!(!tf.is_block_in_main_chain(&block1_id));
        assert!(!tf.is_block_in_main_chain(&block2_id));
        assert!(!tf.is_block_in_main_chain(&block3_id));
        assert!(!tf.is_block_in_main_chain(&block4_id));
        assert!(!tf.is_block_in_main_chain(&block5_id));

        // This will trigger a reorg that should fail.
        tf.create_chain(&block4_id.into(), 2, &mut rng).unwrap_err();

        // Block1 is still not on the mainchain, because the reorg wasn't successful.
        assert!(!tf.is_block_in_main_chain(&block1_id));
        // And it still has the CheckBlockOk status even though it should have been successfully
        // validated, because successful validations that occur during a failed reorg are
        // currently not recorded.
        assert_ok_block_at_stage(block1_status, BlockValidationStage::CheckBlockOk);

        // Block2 is now marked as invalid.
        let block2_status = get_block_status(&tf, &block2_id);
        assert_bad_block_at_stage(block2_status, BlockValidationStage::CheckBlockOk);

        // Blocks 3-5 are also marked as invalid, but for a different reason - one of
        // their ancestors is invalid.
        let block3_status = get_block_status(&tf, &block3_id);
        assert_block_with_bad_parent_at_stage(block3_status, BlockValidationStage::CheckBlockOk);
        let block4_status = get_block_status(&tf, &block4_id);
        assert_block_with_bad_parent_at_stage(block4_status, BlockValidationStage::CheckBlockOk);
        let block5_status = get_block_status(&tf, &block5_id);
        assert_block_with_bad_parent_at_stage(block5_status, BlockValidationStage::CheckBlockOk);
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

        let bad_block = build_block_with_empty_tx(&mut tf, &genesis_id.into());
        let bad_block_id = bad_block.get_id();
        // processing should fail, but we don't care about the exact error.
        tf.process_block(bad_block.clone(), BlockSource::Local).unwrap_err();

        let block_status = get_block_status(&tf, &bad_block_id);
        assert_bad_block(block_status);

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

// Build a block that spends some outputs of its parent.
fn build_block(tf: &mut TestFramework, parent_block: &Id<GenBlock>, rng: &mut impl Rng) -> Block {
    tf.make_block_builder()
        .add_test_transaction_with_parent(*parent_block, rng)
        .with_parent(*parent_block)
        .build()
}

// Process a block that spends some outputs of its parent.
fn process_block(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut impl Rng,
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let block = build_block(tf, parent_block, rng);
    let block_id = block.get_id();
    let result = tf.process_block(block, BlockSource::Local);
    (block_id, result)
}

// Build a block with an invalid tx that has no inputs and outputs.
fn build_block_with_empty_tx(tf: &mut TestFramework, parent_block: &Id<GenBlock>) -> Block {
    let bad_tx = TransactionBuilder::new().build();
    tf.make_block_builder()
        .with_parent(*parent_block)
        .with_transactions(vec![bad_tx])
        .build()
}

// Process a block with an invalid tx that has no inputs and outputs.
fn process_block_with_empty_tx(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let bad_block = build_block_with_empty_tx(tf, parent_block);
    let bad_block_id = bad_block.get_id();
    let result = tf.process_block(bad_block, BlockSource::Local);

    (bad_block_id, result)
}

fn build_block_burn_or_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    burn: bool,
    rng: &mut (impl Rng + CryptoRng),
) -> (Block, SignedTransaction) {
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(*parent_block), 0),
            empty_witness(rng),
        )
        .add_output(if burn {
            TxOutput::Burn(some_coins(rng))
        } else {
            TxOutput::Transfer(some_coins(rng), anyonecanspend_address())
        })
        .build();
    let block = tf
        .make_block_builder()
        .with_transactions(vec![tx.clone()])
        .with_parent(*parent_block)
        .build();

    (block, tx)
}

fn build_block_burn_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Block, SignedTransaction) {
    build_block_burn_or_spend_parent_reward(tf, parent_block, true, rng)
}

fn build_block_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Block, SignedTransaction) {
    build_block_burn_or_spend_parent_reward(tf, parent_block, false, rng)
}

fn process_block_burn_or_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    burn: bool,
    rng: &mut (impl Rng + CryptoRng),
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let (block, _) = build_block_burn_or_spend_parent_reward(tf, parent_block, burn, rng);
    let block_id = block.get_id();
    let result = tf.process_block(block, BlockSource::Local);
    (block_id, result)
}

fn process_block_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    process_block_burn_or_spend_parent_reward(tf, parent_block, false, rng)
}

// Build a block that spends the specified tx.
fn build_block_spend_tx(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    parent_tx: &Id<Transaction>,
    rng: &mut (impl Rng + CryptoRng),
) -> Block {
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo((*parent_tx).into(), 0),
            empty_witness(rng),
        )
        .add_output(TxOutput::Transfer(
            some_coins(rng),
            anyonecanspend_address(),
        ))
        .build();

    tf.make_block_builder()
        .with_transactions(vec![tx])
        .with_parent(*parent_block)
        .build()
}

// Process a block that spends the specified tx.
fn process_block_spend_tx(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    parent_tx: &Id<Transaction>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let block = build_block_spend_tx(tf, parent_block, parent_tx, rng);
    let block_id = block.get_id();
    let result = tf.process_block(block, BlockSource::Local);
    (block_id, result)
}

fn get_block_index(tf: &TestFramework, block_id: &Id<Block>) -> BlockIndex {
    tf.chainstate
        .get_block_index(block_id)
        .unwrap()
        .expect("block index must be present")
}

fn get_block_status(tf: &TestFramework, block_id: &Id<Block>) -> BlockStatus {
    get_block_index(tf, block_id).status()
}

fn assert_fully_valid_block(block_status: BlockStatus) {
    assert!(block_status.is_ok());
    assert!(block_status.is_fully_valid());
}

fn assert_bad_block(block_status: BlockStatus) {
    assert!(!block_status.is_ok());
    assert!(!block_status.is_fully_valid());
}

fn assert_bad_block_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert_bad_block(block_status);
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
    assert!(!block_status.has_invalid_parent());
}

fn assert_block_with_bad_parent_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert_bad_block(block_status);
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
    assert!(block_status.has_invalid_parent());
}

fn assert_ok_block_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert!(block_status.is_ok());
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
}

fn assert_block_data_exists(tf: &TestFramework, block_id: &Id<Block>, should_exist: bool) {
    assert_eq!(
        tf.chainstate.get_block(*block_id).unwrap().is_some(),
        should_exist
    );
}

fn assert_orphan_added_result<T: std::fmt::Debug>(result: Result<T, ChainstateError>) {
    assert_eq!(
        result.unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::OrphanCheckFailed(
            OrphanCheckError::LocalOrphan
        ))
    );
}

fn some_coins(rng: &mut (impl Rng + CryptoRng)) -> OutputValue {
    OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000)))
}

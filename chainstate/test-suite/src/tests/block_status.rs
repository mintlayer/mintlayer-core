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

use chainstate::{BlockError, BlockSource, ChainstateError};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use chainstate_types::{BlockStatus, BlockValidationStage};
use common::{
    chain::{tokens::OutputValue, Block, OutPointSourceId, TxInput, TxOutput},
    primitives::{Amount, Id, Idable},
};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

fn get_block_status(tf: &TestFramework, block_id: &Id<Block>) -> BlockStatus {
    tf.chainstate
        .get_block_index(block_id)
        .unwrap()
        .expect("block index must be present")
        .status()
}

fn some_coins(rng: &mut (impl Rng + CryptoRng)) -> OutputValue {
    OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000)))
}

// Check processing of a good block.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn good_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();
        assert_eq!(tf.best_block_id(), genesis_id);

        let block = tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();
        let block_id = block.get_id();
        let block_index_returned = tf.process_block(block, BlockSource::Local).unwrap();

        // The first block will trigger a trivial reorg, because of which "process_block" will
        // return a BlockIndex. We need to check that it has the correct status too.
        assert!(block_index_returned.is_some());
        assert!(block_index_returned.unwrap().status().is_valid());

        // Now check the status that is stored in the DB.
        let block_status = get_block_status(&tf, &block_id);
        assert!(block_status.is_valid());
    });
}

// Check a failure due to a bad parent block.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn bad_parent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // A tx with no inputs and outputs.
        let tx1 = TransactionBuilder::new().build();

        let block1 = tf.make_block_builder().with_transactions(vec![tx1]).build();
        let block1_id = block1.get_id();
        // process_block should fail, but we don't care about the exact error.
        tf.process_block(block1, BlockSource::Local).unwrap_err();

        let block1_status = get_block_status(&tf, &block1_id);
        assert!(!block1_status.is_valid());

        // Now create a block with a legit tx, but using block1 as the parent.
        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Burn(some_coins(&mut rng)))
            .build();
        let block2 = tf
            .make_block_builder()
            .with_transactions(vec![tx2])
            .with_parent(block1_id.into())
            .build();
        let block2_id = block2.get_id();
        let error = tf.process_block(block2, BlockSource::Local).unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::InvalidParent(block2_id))
        );

        let block2_status = get_block_status(&tf, &block2_id);
        assert_eq!(
            block2_status.last_valid_stage(),
            BlockValidationStage::Initial
        );
    });
}

// Check a failure during the "check_block" phase.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_block_failure(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // Create a bad tx with empty inputs and outputs,
        let tx = TransactionBuilder::new().build();

        let block = tf.make_block_builder().with_transactions(vec![tx]).build();
        let block_id = block.get_id();
        // process_block should fail, but we don't care about the exact error.
        tf.process_block(block, BlockSource::Local).unwrap_err();

        let block_status = get_block_status(&tf, &block_id);
        assert_eq!(
            block_status.last_valid_stage(),
            BlockValidationStage::ParentOk
        );
    });
}

// Check a failure during the "activate_best_chain" phase.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn best_chain_activation_failure(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // In the first block, create a tx that burns some coins.
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Burn(some_coins(&mut rng)))
            .build();
        let block1 = tf.make_block_builder().with_transactions(vec![tx1.clone()]).build();
        let block1_id = block1.get_id();
        tf.process_block(block1, BlockSource::Local).unwrap();

        let block1_status = get_block_status(&tf, &block1_id);
        assert!(block1_status.is_valid());

        // In the second block, create a tx that tries to spend burnt coins.
        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx1.transaction().get_id().into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                some_coins(&mut rng),
                anyonecanspend_address(),
            ))
            .build();

        let block2 = tf.make_block_builder().with_transactions(vec![tx2]).build();
        let block2_id = block2.get_id();
        // process_block should fail, but we don't care about the exact error.
        tf.process_block(block2, BlockSource::Local).unwrap_err();

        let block2_status = get_block_status(&tf, &block2_id);
        assert_eq!(
            block2_status.last_valid_stage(),
            BlockValidationStage::CheckBlockOk
        );
    });
}

// Check processing of a good block.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn good_block_processed_again(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();
        assert_eq!(tf.best_block_id(), genesis_id);

        let block = tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();
        let block_id = block.get_id();
        tf.process_block(block.clone(), BlockSource::Local).unwrap().unwrap();
        let block_status = get_block_status(&tf, &block_id);
        assert!(block_status.is_valid());

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
fn bad_block_processed_again(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // A tx with no inputs and outputs.
        let tx1 = TransactionBuilder::new().build();

        let block1 = tf.make_block_builder().with_transactions(vec![tx1]).build();
        let block1_id = block1.get_id();

        // process_block should fail, but we don't care about the exact error.
        tf.process_block(block1.clone(), BlockSource::Local).unwrap_err();

        let block1_status = get_block_status(&tf, &block1_id);
        assert!(!block1_status.is_valid());

        // Process it again
        let error = tf.process_block(block1, BlockSource::Local).unwrap_err();
        assert_eq!(
            error,
            ChainstateError::ProcessBlockError(BlockError::InvalidBlockAlreadyProcessed(block1_id))
        );
    });
}

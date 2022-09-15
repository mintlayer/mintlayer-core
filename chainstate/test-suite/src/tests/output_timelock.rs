// Copyright (c) 2021 RBB S.r.l
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

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use common::time_getter::TimeGetter;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, GenBlock},
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::OutputValue,
        OutPointSourceId, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{time, Amount, BlockDistance, BlockHeight, Id, Idable},
};

use chainstate::BlockError;
use chainstate::ChainstateError;
use chainstate::ConnectTransactionError;
use chainstate_test_framework::anyonecanspend_address;
use chainstate_test_framework::TestFramework;
use chainstate_test_framework::TransactionBuilder;

#[test]
fn output_lock_until_height() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        let block_height_that_unlocks = 10;

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::UntilHeight(BlockHeight::new(block_height_that_unlocks)),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(locked_output.clone())
                        .add_anyone_can_spend_output(5000)
                        .build()
                )
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(1));

        // create another block, and spend the first input from the previous block
        let prev_block_info = tf.block_info(1);
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        prev_block_info.txns[0].0.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_anyone_can_spend_output(10000)
                    .build(),
            )
            .build_and_process()
            .unwrap();
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(2));

        // let's create more blocks until block_height_that_unlocks - 1, and always fail to spend, and build up the chain
        for height in 3..block_height_that_unlocks {
            assert_eq!(
                BlockHeight::new(height - 1),
                tf.best_block_index().block_height()
            );
            logging::log::info!("Submitting block of height: {}", height);

            // Create another block, and spend the first input from the previous block.
            assert_eq!(
                tf.make_block_builder()
                    .add_transaction(
                        TransactionBuilder::new()
                            .add_input(locked_output.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation
                ))
            );
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height - 1)
            );

            // create another block, with no transactions, and get the blockchain to progress
            tf.make_block_builder().build_and_process().unwrap();
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height)
            );
        }

        // now we should be able to spend it at block_height_that_unlocks
        assert_eq!(
            tf.best_block_id(),
            tf.block_info(block_height_that_unlocks - 1).id
        );
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(locked_output)
                    .add_anyone_can_spend_output(5000)
                    .build(),
            )
            .build_and_process()
            .unwrap();
        assert_eq!(
            tf.best_block_index().block_height(),
            BlockHeight::new(block_height_that_unlocks)
        );
    });
}

#[test]
fn output_lock_until_height_but_spend_at_same_block() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        let block_height_that_unlocks = 10;

        // create the first block, with a locked output
        let prev_block = tf.genesis();

        let tx1 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::BlockReward(<Id<GenBlock>>::from(prev_block.get_id())),
                0,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100000)),
                OutputPurpose::LockThenTransfer(
                    anyonecanspend_address(),
                    OutputTimeLock::UntilHeight(BlockHeight::new(block_height_that_unlocks)),
                ),
            ))
            .build();
        let tx2 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(5000)
            .build();

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[test]
fn output_lock_for_block_count() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        let block_count_that_unlocks = 20;
        let block_height_with_locked_output = 1;

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(locked_output.clone())
                        .add_anyone_can_spend_output(5000)
                        .build()
                )
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(1));

        // create another block, and spend the first input from the previous block
        let prev_block_info = tf.best_block_info();
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        prev_block_info.txns[0].0.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_anyone_can_spend_output(10000)
                    .build(),
            )
            .build_and_process()
            .unwrap();
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(2));

        // let's create more blocks until block_count_that_unlocks + block_height_with_locked_output, and always fail to spend, and build up the chain
        for height in 3..block_count_that_unlocks + block_height_with_locked_output {
            assert_eq!(
                BlockHeight::new(height - 1),
                tf.best_block_index().block_height()
            );
            logging::log::info!("Submitting block of height: {}", height);

            // create another block, and spend the first input from the previous block
            assert_eq!(
                tf.make_block_builder()
                    .add_transaction(
                        TransactionBuilder::new()
                            .add_input(locked_output.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation
                ))
            );
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height - 1)
            );

            // create another block, with no transactions, and get the blockchain to progress
            tf.make_block_builder().build_and_process().unwrap();
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height)
            );
        }

        // now we should be able to spend it at block_count_that_unlocks
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(locked_output)
                    .add_anyone_can_spend_output(5000)
                    .build(),
            )
            .build_and_process()
            .unwrap();
        assert_eq!(
            tf.best_block_index().block_height(),
            BlockHeight::new(block_count_that_unlocks + block_height_with_locked_output)
        );
    });
}

#[test]
fn output_lock_for_block_count_but_spend_at_same_block() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        let block_count_that_unlocks = 10;

        // create the first block, with a locked output
        let tx1 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::BlockReward(<Id<GenBlock>>::from(tf.genesis().get_id())),
                0,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100000)),
                OutputPurpose::LockThenTransfer(
                    anyonecanspend_address(),
                    OutputTimeLock::ForBlockCount(block_count_that_unlocks),
                ),
            ))
            .build();
        let tx2 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(50000)
            .build();
        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[test]
fn output_lock_for_block_count_attempted_overflow() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        let block_count_that_unlocks = u64::MAX;

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(locked_output)
                        .add_anyone_can_spend_output(5000)
                        .build()
                )
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::BlockHeightArithmeticError
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(1));
    });
}

#[test]
fn output_lock_until_time() {
    utils::concurrency::model(|| {
        let current_time = Arc::new(AtomicU64::new(1));
        let current_time_ = Arc::clone(&current_time);
        let time_getter = TimeGetter::new(Arc::new(move || {
            Duration::from_secs(current_time_.load(Ordering::SeqCst))
        }));
        let mut tf = TestFramework::builder().with_time_getter(time_getter).build();

        let genesis_timestamp = tf.genesis().timestamp();
        let lock_time = genesis_timestamp.as_int_seconds() + 4;
        let block_times: Vec<_> = itertools::iterate(genesis_timestamp.as_int_seconds(), |t| t + 1)
            .take(8)
            .collect();
        // Check that without the last block the output remains locked.
        assert_eq!(
            median_block_time(&block_times[..block_times.len() - 1]),
            lock_time - 1
        );
        // Check that the last block allows to unlock the output.
        assert_eq!(median_block_time(&block_times), lock_time);

        current_time.store(*block_times.last().unwrap(), Ordering::SeqCst);

        let expected_height = 1;
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(lock_time)),
            BlockTimestamp::from_int_seconds(block_times[expected_height]),
        );
        assert_eq!(
            tf.best_block_index().block_height(),
            BlockHeight::new(expected_height as u64),
        );

        // Skip the genesis block and the block that contains the locked output.
        for (block_time, height) in block_times.iter().skip(2).zip(expected_height..) {
            assert_eq!(
                tf.chainstate.calculate_median_time_past(&tf.best_block_id()).as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            assert_eq!(
                tf.make_block_builder()
                    .add_transaction(
                        TransactionBuilder::new()
                            .add_input(locked_output.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .with_timestamp(BlockTimestamp::from_int_seconds(*block_time))
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation
                ))
            );
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height as u64),
            );
            // Create another block, with no transactions, and get the blockchain to progress.
            tf.make_block_builder()
                .with_timestamp(BlockTimestamp::from_int_seconds(*block_time))
                .build_and_process()
                .unwrap();
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height as u64 + 1),
            );
        }

        // Check that the output can now be spent.
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(locked_output)
                    .add_anyone_can_spend_output(5000)
                    .build(),
            )
            // The block that is being validated isn't taken into account when calculating the
            // median time, so any time can be used here.
            .with_timestamp(BlockTimestamp::from_int_seconds(
                *block_times.last().unwrap(),
            ))
            .build_and_process()
            .unwrap();
        assert_eq!(
            tf.best_block_index().block_height(),
            BlockHeight::new(block_times.len() as u64)
        );
    });
}

#[test]
fn output_lock_until_time_but_spend_at_same_block() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        let genesis_timestamp = tf.genesis().timestamp();
        let lock_time = genesis_timestamp.as_int_seconds() + 3;

        // create the first block, with a locked output
        let tx1 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::BlockReward(<Id<GenBlock>>::from(tf.genesis().get_id())),
                0,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100000)),
                OutputPurpose::LockThenTransfer(
                    anyonecanspend_address(),
                    OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(lock_time)),
                ),
            ))
            .build();

        let tx2 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(50000)
            .build();

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[test]
fn output_lock_for_seconds() {
    utils::concurrency::model(|| {
        let current_time = Arc::new(AtomicU64::new(1));
        let current_time_ = Arc::clone(&current_time);
        let time_getter = TimeGetter::new(Arc::new(move || {
            Duration::from_secs(current_time_.load(Ordering::SeqCst))
        }));
        let mut tf = TestFramework::builder().with_time_getter(time_getter).build();

        let genesis_timestamp = tf.genesis().timestamp();
        let block_times: Vec<_> = itertools::iterate(genesis_timestamp.as_int_seconds(), |t| t + 1)
            .take(8)
            .collect();
        let lock_seconds = 3;
        let unlock_time = block_times[1] + lock_seconds;
        // Check that without the last block the output remains locked.
        assert_eq!(
            median_block_time(&block_times[..block_times.len() - 1]),
            unlock_time - 1
        );
        // Check that the last block allows to unlock the output.
        assert_eq!(median_block_time(&block_times), unlock_time);

        current_time.store(*block_times.last().unwrap(), Ordering::SeqCst);

        let expected_height = 1;
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForSeconds(lock_seconds),
            BlockTimestamp::from_int_seconds(block_times[expected_height]),
        );
        assert_eq!(
            tf.best_block_index().block_height(),
            BlockHeight::new(expected_height as u64),
        );

        // Skip the genesis block and the block that contains the locked output.
        for (block_time, height) in block_times.iter().skip(2).zip(expected_height..) {
            assert_eq!(
                tf.chainstate.calculate_median_time_past(&tf.best_block_id()).as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            assert_eq!(
                tf.make_block_builder()
                    .add_transaction(
                        TransactionBuilder::new()
                            .add_input(locked_output.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .with_timestamp(BlockTimestamp::from_int_seconds(*block_time))
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation
                ))
            );
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height as u64),
            );

            // Create another block, with no transactions, and get the blockchain to progress.
            tf.make_block_builder()
                .with_timestamp(BlockTimestamp::from_int_seconds(*block_time))
                .build_and_process()
                .unwrap();
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height as u64 + 1),
            );
        }

        // Check that the output can now be spent.
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(locked_output)
                    .add_anyone_can_spend_output(5000)
                    .build(),
            )
            // The block that is being validated isn't taken into account when calculating the
            // median time, so any time can be used here.
            .with_timestamp(BlockTimestamp::from_int_seconds(
                *block_times.last().unwrap(),
            ))
            .build_and_process()
            .unwrap();
        assert_eq!(
            tf.best_block_index().block_height(),
            BlockHeight::new(block_times.len() as u64)
        );
    });
}

#[test]
fn output_lock_for_seconds_but_spend_at_same_block() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        // create the first block, with a locked output
        let tx1 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::BlockReward(<Id<GenBlock>>::from(tf.genesis().get_id())),
                0,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100000)),
                OutputPurpose::LockThenTransfer(
                    anyonecanspend_address(),
                    OutputTimeLock::ForSeconds(100),
                ),
            ))
            .build();

        let tx2 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            ))
            .add_anyone_can_spend_output(50000)
            .build();

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[test]
fn output_lock_for_seconds_attempted_overflow() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForSeconds(u64::MAX),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(locked_output)
                        .add_anyone_can_spend_output(5000)
                        .build()
                )
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::BlockTimestampArithmeticError
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(1));
    });
}

/// Adds a block with the locked output and returns input corresponding to this output.
fn add_block_with_locked_output(
    tf: &mut TestFramework,
    output_time_lock: OutputTimeLock,
    timestamp: BlockTimestamp,
) -> TxInput {
    // Find the last block.
    let current_height = tf.best_block_index().block_height();
    let prev_block_info = tf.block_info(current_height.into());

    tf.make_block_builder()
        .add_transaction(
            TransactionBuilder::new()
                .add_input(TxInput::new(
                    prev_block_info.txns[0].0.clone(),
                    0,
                    InputWitness::NoSignature(None),
                ))
                .add_anyone_can_spend_output(10000)
                .add_output(TxOutput::new(
                    OutputValue::Coin(Amount::from_atoms(100000)),
                    OutputPurpose::LockThenTransfer(anyonecanspend_address(), output_time_lock),
                ))
                .build(),
        )
        .with_timestamp(timestamp)
        .build_and_process()
        .unwrap();

    let new_height = (current_height + BlockDistance::new(1)).unwrap();
    assert_eq!(tf.best_block_index().block_height(), new_height);

    let block_info = tf.block_info(new_height.into());
    TxInput::new(
        block_info.txns[0].0.clone(),
        1,
        InputWitness::NoSignature(None),
    )
}

fn median_block_time(times: &[u64]) -> u64 {
    // Only the last 11 blocks are used for calculating the median time.
    assert!(times.len() < 11);
    times[times.len() / 2]
}

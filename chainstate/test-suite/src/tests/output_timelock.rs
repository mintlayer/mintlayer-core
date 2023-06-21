// Copyright (c) 2021-2022 RBB S.r.l
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

use std::sync::Arc;

use common::{
    chain::{
        block::{timestamp::BlockTimestamp, GenBlock},
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::OutputValue,
        OutPointSourceId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use rstest::rstest;

use super::helpers::add_block_with_locked_output;
use chainstate::BlockError;
use chainstate::ChainstateError;
use chainstate::ConnectTransactionError;
use chainstate_test_framework::anyonecanspend_address;
use chainstate_test_framework::TestFramework;
use chainstate_test_framework::TransactionBuilder;
use test_utils::{
    mock_time_getter::mocked_time_getter_seconds,
    random::{make_seedable_rng, Seed},
};
use utils::atomics::SeqCstAtomicU64;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_until_height(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let block_height_that_unlocks = 10;

        // create the first block, with a locked output
        let current_time = tf.current_time();
        let (input_witness, locked_input, _) = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::UntilHeight(BlockHeight::new(block_height_that_unlocks)),
            BlockTimestamp::from_duration_since_epoch(current_time),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(locked_input.clone(), input_witness.clone())
                        .add_anyone_can_spend_output(5000)
                        .build()
                )
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation(
                    locked_input.utxo_outpoint().unwrap().clone()
                )
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(1));

        // create another block, and spend the first input from the previous block
        let prev_block_outputs = tf.outputs_from_genblock(tf.block_id(1));
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(prev_block_outputs.keys().next().unwrap().clone(), 0),
                        InputWitness::NoSignature(None),
                    )
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
                            .add_input(locked_input.clone(), input_witness.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation(
                        locked_input.utxo_outpoint().unwrap().clone()
                    )
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
            tf.block_id(block_height_that_unlocks - 1)
        );
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(locked_input, input_witness)
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_until_height_but_spend_at_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let block_height_that_unlocks = 10;

        // create the first block, with a locked output
        let prev_block = tf.genesis();

        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(<Id<GenBlock>>::from(prev_block.get_id())),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(100000)),
                anyonecanspend_address(),
                OutputTimeLock::UntilHeight(BlockHeight::new(block_height_that_unlocks)),
            ))
            .build();
        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx1.transaction().get_id()), 1),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(5000)
            .build();
        let locked_outpoint = UtxoOutPoint::new(tx1.transaction().get_id().into(), 1);

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation(locked_outpoint)
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_block_count(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let block_count_that_unlocks = 20;
        let block_height_with_locked_output = 1;

        // create the first block, with a locked output
        let current_time = tf.current_time();
        let (input_witness, input, _) = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            BlockTimestamp::from_duration_since_epoch(current_time),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(input.clone(), input_witness.clone())
                        .add_anyone_can_spend_output(5000)
                        .build()
                )
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation(input.utxo_outpoint().unwrap().clone())
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(1));

        // create another block, and spend the first input from the previous block
        let prev_block_outputs = tf.outputs_from_genblock(tf.best_block_id());
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(prev_block_outputs.keys().next().unwrap().clone(), 0),
                        InputWitness::NoSignature(None),
                    )
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
                            .add_input(input.clone(), input_witness.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation(
                        input.utxo_outpoint().unwrap().clone()
                    )
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
                    .add_input(input, input_witness)
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_block_count_but_spend_at_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let block_count_that_unlocks = 10;

        // create the first block, with a locked output
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(<Id<GenBlock>>::from(tf.genesis().get_id())),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(100000)),
                anyonecanspend_address(),
                OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            ))
            .build();
        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx1.transaction().get_id()), 1),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(50000)
            .build();
        let locked_outpoint = UtxoOutPoint::new(tx1.transaction().get_id().into(), 1);

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation(locked_outpoint)
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_block_count_attempted_overflow(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let block_count_that_unlocks = u64::MAX;

        // create the first block, with a locked output
        let current_time = tf.current_time();
        let (input_witness, input, _) = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            BlockTimestamp::from_duration_since_epoch(current_time),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(input, input_witness)
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_until_time(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let current_time = Arc::new(SeqCstAtomicU64::new(1));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&current_time));
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).with_time_getter(time_getter).build();

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

        current_time.store(*block_times.last().unwrap());

        let expected_height = 1;
        let (input_witness, input, _) = add_block_with_locked_output(
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
            let mtp = tf.chainstate.calculate_median_time_past(&tf.best_block_id()).unwrap();
            assert_eq!(
                mtp.as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            assert_eq!(
                tf.make_block_builder()
                    .add_transaction(
                        TransactionBuilder::new()
                            .add_input(input.clone(), input_witness.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .with_timestamp(BlockTimestamp::from_int_seconds(*block_time))
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation(
                        input.utxo_outpoint().unwrap().clone()
                    )
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
                    .add_input(input, input_witness)
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_until_time_but_spend_at_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let genesis_timestamp = tf.genesis().timestamp();
        let lock_time = genesis_timestamp.as_int_seconds() + 3;

        // create the first block, with a locked output
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(<Id<GenBlock>>::from(tf.genesis().get_id())),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(100000)),
                anyonecanspend_address(),
                OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(lock_time)),
            ))
            .build();

        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx1.transaction().get_id()), 1),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(50000)
            .build();
        let locked_outpoint = UtxoOutPoint::new(tx1.transaction().get_id().into(), 1);

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation(locked_outpoint)
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_seconds(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let current_time = Arc::new(SeqCstAtomicU64::new(1));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&current_time));
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).with_time_getter(time_getter).build();

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

        current_time.store(*block_times.last().unwrap());

        let expected_height = 1;
        let (input_witness, input, _) = add_block_with_locked_output(
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
            let mtp = tf.chainstate.calculate_median_time_past(&tf.best_block_id()).unwrap();
            assert_eq!(
                mtp.as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            assert_eq!(
                tf.make_block_builder()
                    .add_transaction(
                        TransactionBuilder::new()
                            .add_input(input.clone(), input_witness.clone())
                            .add_anyone_can_spend_output(5000)
                            .build()
                    )
                    .with_timestamp(BlockTimestamp::from_int_seconds(*block_time))
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::TimeLockViolation(
                        input.utxo_outpoint().unwrap().clone()
                    )
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
                    .add_input(input, input_witness)
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_seconds_but_spend_at_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // create the first block, with a locked output
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(<Id<GenBlock>>::from(tf.genesis().get_id())),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(10000)
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(100000)),
                anyonecanspend_address(),
                OutputTimeLock::ForSeconds(100),
            ))
            .build();

        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx1.transaction().get_id()), 1),
                InputWitness::NoSignature(None),
            )
            .add_anyone_can_spend_output(50000)
            .build();
        let locked_outpoint = UtxoOutPoint::new(tx1.transaction().get_id().into(), 1);

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TimeLockViolation(locked_outpoint)
            ))
        );
        assert_eq!(tf.best_block_index().block_height(), BlockHeight::new(0));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_seconds_attempted_overflow(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // create the first block, with a locked output
        let current_time = tf.current_time();
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForSeconds(u64::MAX),
            BlockTimestamp::from_duration_since_epoch(current_time),
        );

        // attempt to create the next block, and attempt to spend the locked output
        assert_eq!(
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(locked_output.1, locked_output.0)
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

fn median_block_time(times: &[u64]) -> u64 {
    // Only the last 11 blocks are used for calculating the median time.
    assert!(times.len() < 11);
    times[times.len() / 2]
}

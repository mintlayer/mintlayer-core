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

use super::helpers::add_block_with_locked_output;
use super::helpers::in_memory_storage_wrapper::InMemoryStorageWrapper;

use chainstate::ConnectTransactionError;
use chainstate_test_framework::{TestFramework, TestStore, TransactionBuilder};
use common::{
    chain::{
        block::timestamp::BlockTimestamp, config::Builder as ConfigBuilder,
        timelock::OutputTimeLock, ChainConfig,
    },
    primitives::{time, BlockHeight},
};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use tx_verifier::transaction_verifier::{
    config::TransactionVerifierConfig, TransactionSourceForConnect, TransactionVerifier,
};

fn setup(rng: &mut (impl Rng + CryptoRng)) -> (ChainConfig, InMemoryStorageWrapper, TestFramework) {
    let storage = TestStore::new_empty().unwrap();
    let tf = TestFramework::builder(rng).with_storage(storage.clone()).build();

    let chain_config = ConfigBuilder::test_chain().build();
    let storage = InMemoryStorageWrapper::new(storage, chain_config.clone());

    (chain_config, storage, tf)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_until_height(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup(&mut rng);
        let mut verifier = TransactionVerifier::new(
            &storage,
            &chain_config,
            TransactionVerifierConfig::new(true),
        );

        let block_height_that_unlocks = 10;

        let current_time = tf.current_time();
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::UntilHeight(BlockHeight::new(block_height_that_unlocks)),
            BlockTimestamp::from_duration_since_epoch(current_time),
        );

        let spend_locked_tx = TransactionBuilder::new()
            .add_input(locked_output.1.clone(), locked_output.0)
            .add_anyone_can_spend_output(5000)
            .build();

        // let's create more blocks until block_height_that_unlocks - 1, and always fail to spend, and build up the chain
        for height in 2..block_height_that_unlocks {
            // attempt to spend the locked output
            let best_block_index = match tf.best_block_index() {
                chainstate_types::GenBlockIndex::Block(block_index) => block_index,
                chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
            };
            assert_eq!(
                verifier.connect_transaction(
                    &TransactionSourceForConnect::Mempool {
                        current_best: &best_block_index,
                    },
                    &spend_locked_tx,
                    &BlockTimestamp::from_duration_since_epoch(tf.current_time()),
                ),
                Err(ConnectTransactionError::TimeLockViolation)
            );

            tf.make_block_builder().build_and_process().unwrap();
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height)
            );
        }

        // now we should be able to spend it at block_height_that_unlocks
        let best_block_index = match tf.best_block_index() {
            chainstate_types::GenBlockIndex::Block(block_index) => block_index,
            chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
        };
        verifier
            .connect_transaction(
                &TransactionSourceForConnect::Mempool {
                    current_best: &best_block_index,
                },
                &spend_locked_tx,
                &BlockTimestamp::from_duration_since_epoch(tf.current_time()),
            )
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_block_count(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup(&mut rng);
        let mut verifier = TransactionVerifier::new(
            &storage,
            &chain_config,
            TransactionVerifierConfig::new(true),
        );

        let block_count_that_unlocks = 20;
        let block_height_with_locked_output = 1;

        // create the first block, with a locked output
        let current_time = tf.current_time();
        let locked_output = add_block_with_locked_output(
            &mut tf,
            OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            BlockTimestamp::from_duration_since_epoch(current_time),
        );

        let spend_locked_tx = TransactionBuilder::new()
            .add_input(locked_output.1.clone(), locked_output.0)
            .add_anyone_can_spend_output(5000)
            .build();

        // let's create more blocks until block_count_that_unlocks + block_height_with_locked_output, and always fail to spend, and build up the chain
        for height in 2..block_count_that_unlocks + block_height_with_locked_output {
            // attempt to spend the locked output
            let best_block_index = match tf.best_block_index() {
                chainstate_types::GenBlockIndex::Block(block_index) => block_index,
                chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
            };
            assert_eq!(
                verifier.connect_transaction(
                    &TransactionSourceForConnect::Mempool {
                        current_best: &best_block_index,
                    },
                    &spend_locked_tx,
                    &BlockTimestamp::from_duration_since_epoch(tf.current_time()),
                ),
                Err(ConnectTransactionError::TimeLockViolation)
            );

            // create another block, with no transactions, and get the blockchain to progress
            tf.make_block_builder().build_and_process().unwrap();
            assert_eq!(
                tf.best_block_index().block_height(),
                BlockHeight::new(height)
            );
        }

        // now we should be able to spend it at block_count_that_unlocks

        // attempt to spend the locked output
        let best_block_index = match tf.best_block_index() {
            chainstate_types::GenBlockIndex::Block(block_index) => block_index,
            chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
        };
        verifier
            .connect_transaction(
                &TransactionSourceForConnect::Mempool {
                    current_best: &best_block_index,
                },
                &spend_locked_tx,
                &BlockTimestamp::from_duration_since_epoch(tf.current_time()),
            )
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_until_time(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup(&mut rng);
        let mut verifier = TransactionVerifier::new(
            &storage,
            &chain_config,
            TransactionVerifierConfig::new(true),
        );

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

        tf.set_time_seconds_since_epoch(*block_times.last().unwrap());

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

        let spend_locked_tx = TransactionBuilder::new()
            .add_input(locked_output.1.clone(), locked_output.0)
            .add_anyone_can_spend_output(5000)
            .build();

        // Skip the genesis block and the block that contains the locked output.
        for (block_time, height) in block_times.iter().skip(2).zip(expected_height..) {
            let mtp = tf.chainstate.calculate_median_time_past(&tf.best_block_id()).unwrap();
            assert_eq!(
                mtp.as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            let best_block_index = match tf.best_block_index() {
                chainstate_types::GenBlockIndex::Block(block_index) => block_index,
                chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
            };
            assert_eq!(
                verifier.connect_transaction(
                    &TransactionSourceForConnect::Mempool {
                        current_best: &best_block_index,
                    },
                    &spend_locked_tx,
                    &mtp
                ),
                Err(ConnectTransactionError::TimeLockViolation)
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
        let best_block_index = match tf.best_block_index() {
            chainstate_types::GenBlockIndex::Block(block_index) => block_index,
            chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
        };
        verifier
            .connect_transaction(
                &TransactionSourceForConnect::Mempool {
                    current_best: &best_block_index,
                },
                &spend_locked_tx,
                &BlockTimestamp::from_duration_since_epoch(tf.current_time()),
            )
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn output_lock_for_seconds(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup(&mut rng);
        let mut verifier = TransactionVerifier::new(
            &storage,
            &chain_config,
            TransactionVerifierConfig::new(true),
        );

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

        tf.set_time_seconds_since_epoch(*block_times.last().unwrap());

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

        let spend_locked_tx = TransactionBuilder::new()
            .add_input(locked_output.1.clone(), locked_output.0)
            .add_anyone_can_spend_output(5000)
            .build();

        // Skip the genesis block and the block that contains the locked output.
        for (block_time, height) in block_times.iter().skip(2).zip(expected_height..) {
            let mtp = tf.chainstate.calculate_median_time_past(&tf.best_block_id()).unwrap();
            assert_eq!(
                mtp.as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            let best_block_index = match tf.best_block_index() {
                chainstate_types::GenBlockIndex::Block(block_index) => block_index,
                chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
            };
            assert_eq!(
                verifier.connect_transaction(
                    &TransactionSourceForConnect::Mempool {
                        current_best: &best_block_index,
                    },
                    &spend_locked_tx,
                    &mtp
                ),
                Err(ConnectTransactionError::TimeLockViolation)
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
        let best_block_index = match tf.best_block_index() {
            chainstate_types::GenBlockIndex::Block(block_index) => block_index,
            chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
        };
        verifier
            .connect_transaction(
                &TransactionSourceForConnect::Mempool {
                    current_best: &best_block_index,
                },
                &spend_locked_tx,
                &BlockTimestamp::from_duration_since_epoch(time::get_time()),
            )
            .unwrap();
    });
}

fn median_block_time(times: &[u64]) -> u64 {
    // Only the last 11 blocks are used for calculating the median time.
    assert!(times.len() < 11);
    times[times.len() / 2]
}

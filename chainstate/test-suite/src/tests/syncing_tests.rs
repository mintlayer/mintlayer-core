// Copyright (c) 2022 RBB S.r.l
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

use std::{iter, time::Duration};

use rstest::rstest;

use chainstate::{BlockSource, ChainstateConfig, ChainstateError, HEADER_LIMIT};
use chainstate_test_framework::TestFramework;
use chainstate_types::PropertyQueryError;
use common::{
    chain::{block::timestamp::BlockTimestamp, GenBlock},
    primitives::{BlockDistance, BlockHeight, Id, Idable},
};
use crypto::random::Rng;
use test_utils::random::{make_seedable_rng, Seed};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn process_a_trivial_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut btf = TestFramework::builder(&mut rng).build();
    btf.make_block_builder().build_and_process().unwrap();
}

// Generate some blocks and check that a locator is of expected length.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_locator(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut btf = TestFramework::builder(&mut rng).build();

        let locator = btf.chainstate.get_locator().unwrap();
        assert_eq!(locator.len(), 1);
        assert_eq!(&locator[0], &btf.genesis().get_id());

        // Expand the chain several times.
        let mut blocks = 1;
        let mut last_block_id: Id<GenBlock> = btf.genesis().get_id().into();
        for _ in 0..8 {
            let new_blocks = rng.gen_range(1..2000);
            last_block_id = btf.create_chain(&last_block_id, new_blocks, &mut rng).unwrap();
            blocks += new_blocks;

            // Check the locator length.
            let locator = btf.chainstate.get_locator().unwrap();
            assert_eq!(locator.len(), (blocks as f64).log2().ceil() as usize + 1);

            // Check the locator headers.
            let height =
                btf.chainstate.get_block_height_in_main_chain(&last_block_id).unwrap().unwrap();
            assert_eq!(&locator[0], &last_block_id);
            for (i, header) in locator.iter().skip(1).enumerate() {
                let idx = height - BlockDistance::new(2i64.pow(i as u32));
                let expected =
                    btf.chainstate.get_block_id_from_height(&idx.unwrap()).unwrap().unwrap();
                assert_eq!(&expected, header);
            }
        }
    });
}

// Check that new blocks (produced after a locator is created) are returned.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let header_limit = i64::from(HEADER_LIMIT).try_into().unwrap();
        let headers_count = rng.gen_range(1000..header_limit);
        let blocks_count = rng.gen_range(1000..2000);

        let mut tf = TestFramework::builder(&mut rng).build();
        let mut last_block_id = tf.genesis().get_id().into();
        last_block_id = tf.create_chain(&last_block_id, blocks_count, &mut rng).unwrap();

        // The locator is from this exact chain, so `get_headers` should return an empty sequence.
        let locator = tf.chainstate.get_locator().unwrap();
        assert_eq!(tf.chainstate.get_headers(locator.clone()).unwrap(), vec![]);

        // Produce more blocks. Now `get_headers` should return these blocks.
        let expected: Vec<_> = iter::from_fn(|| {
            let block = tf
                .make_block_builder()
                .with_parent(last_block_id)
                .add_test_transaction_from_best_block(&mut rng)
                .build();
            last_block_id = block.get_id().into();
            let header = block.header().clone();
            tf.process_block(block, BlockSource::Peer).unwrap().unwrap();
            Some(header)
        })
        .take(headers_count)
        .collect();

        let headers = tf.chainstate.get_headers(locator.clone()).unwrap();
        assert_eq!(headers, expected);
        // Because both the locator and chainstate are tracking the same chain, the first header of
        // the locator is always the parent of the first new block.
        assert_eq!(expected[0].prev_block_id(), &locator[0]);

        // Produce more blocks than `HEADER_LIMIT`, so get_headers is truncated.
        tf.create_chain(&last_block_id, header_limit - expected.len(), &mut rng)
            .unwrap();
        let headers = tf.chainstate.get_headers(locator).unwrap();
        assert_eq!(headers.len(), header_limit);
    });
}

// Create two chains that only share the genesis block and verify that the header is attached to
// the genesis.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_genesis(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let mut btf = TestFramework::builder(&mut rng).build();
        let genesis_id: Id<GenBlock> = btf.genesis().get_id().into();

        btf.create_chain(&genesis_id, rng.gen_range(64..128), &mut rng).unwrap();
        let locator_1 = btf.chainstate.get_locator().unwrap();

        let chain_length = rng.gen_range(1200..2000);
        btf.create_chain(&genesis_id, chain_length, &mut rng).unwrap();
        let locator_2 = btf.chainstate.get_locator().unwrap();
        assert_ne!(locator_1, locator_2);
        assert!(locator_1.len() < locator_2.len());

        let headers = btf.chainstate.get_headers(locator_1).unwrap();
        assert_eq!(headers[0].prev_block_id(), &genesis_id);
        assert_eq!(headers.len(), chain_length);
    });
}

// Create two chains that branch at some point, both with some unique blocks. Verify that the first
// returned header is attached to a block that is known to both chains.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_branching_chains(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let common_height = rng.gen_range(100..10_000);

        let mut tf = TestFramework::builder(&mut rng).build();
        let common_block_id =
            tf.create_chain(&tf.genesis().get_id().into(), common_height, &mut rng).unwrap();

        tf.create_chain(&common_block_id, rng.gen_range(100..2500), &mut rng).unwrap();
        let locator = tf.chainstate.get_locator().unwrap();
        tf.create_chain(&common_block_id, rng.gen_range(2500..5000), &mut rng).unwrap();

        let headers = tf.chainstate.get_headers(locator).unwrap();
        let id = headers[0].prev_block_id();
        assert!(tf.block_index(id).block_height() <= BlockHeight::new(common_height as u64));
    });
}

// Create two separate chains that share some blocks. Verify that the first returned header is
// attached to some block known for both chains.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_different_chains(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let mut tf1 = TestFramework::builder(&mut rng).build();
        let mut tf2 = TestFramework::builder(&mut rng).build();

        assert_eq!(tf1.genesis().get_id(), tf2.genesis().get_id());
        assert_eq!(
            tf1.outputs_from_genblock(tf1.genesis().get_id().into()),
            tf2.outputs_from_genblock(tf2.genesis().get_id().into())
        );
        let mut prev_id = tf1.genesis().get_id().into();
        for _ in 0..rng.gen_range(100..250) {
            let block = tf1
                .make_block_builder()
                .with_parent(prev_id)
                .add_test_transaction_from_best_block(&mut rng)
                .build();
            prev_id = block.get_id().into();
            tf1.process_block(block.clone(), BlockSource::Local).unwrap();
            tf2.process_block(block.clone(), BlockSource::Local).unwrap();
            assert_eq!(tf1.best_block_id(), tf2.best_block_id());
        }

        tf1.create_chain(&prev_id, rng.gen_range(32..256), &mut rng).unwrap();
        tf2.create_chain(&prev_id, rng.gen_range(256..512), &mut rng).unwrap();

        let locator = tf1.chainstate.get_locator().unwrap();
        let headers = tf2.chainstate.get_headers(locator).unwrap();
        let id = *headers[0].prev_block_id();
        tf1.block_index(&id); // This panics if the ID is not found

        let locator = tf2.chainstate.get_locator().unwrap();
        let headers = tf1.chainstate.get_headers(locator).unwrap();
        let id = *headers[0].prev_block_id();
        tf2.block_index(&id); // This panics if the ID is not found
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn filter_already_existing_blocks(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let mut tf1 = TestFramework::builder(&mut rng).build();
        let mut tf2 = TestFramework::builder(&mut rng).build();

        let mut prev1_id = tf1.genesis().get_id().into();
        for _ in 0..rng.gen_range(8..16) {
            let block = tf1
                .make_block_builder()
                .with_parent(prev1_id)
                .add_test_transaction_from_best_block(&mut rng)
                .build();
            prev1_id = block.get_id().into();
            tf1.process_block(block.clone(), BlockSource::Local).unwrap();
            tf2.process_block(block.clone(), BlockSource::Local).unwrap();
            assert_eq!(tf1.best_block_id(), tf2.best_block_id());
        }

        let limit = rng.gen_range(32..256);
        let mut prev2_id = prev1_id;
        let mut headers1 = vec![];
        let mut headers2 = vec![];

        // Add random blocks to both chains.
        for i in 0..(limit * 2) {
            if i <= limit {
                let block = tf1
                    .make_block_builder()
                    .with_parent(prev1_id)
                    .add_test_transaction_with_parent(prev1_id, &mut rng)
                    .build();
                prev1_id = block.get_id().into();
                headers1.push(block.header().clone());
                tf1.process_block(block, BlockSource::Local).unwrap();
            }

            let block = tf2
                .make_block_builder()
                .with_parent(prev2_id)
                .add_test_transaction_with_parent(prev2_id, &mut rng)
                .build();
            prev2_id = block.get_id().into();
            headers2.push(block.header().clone());
            tf2.process_block(block, BlockSource::Local).unwrap();
        }

        // Check that filter_already_existing_blocks retains only unique to other chain blocks.
        let locator = tf1.chainstate.get_locator().unwrap();
        let headers = tf2.chainstate.get_headers(locator).unwrap();
        assert!(headers.len() >= headers2.len());
        let headers = tf1.chainstate.filter_already_existing_blocks(headers).unwrap();
        assert_eq!(headers, headers2);

        let locator = tf2.chainstate.get_locator().unwrap();
        let headers = tf1.chainstate.get_headers(locator).unwrap();
        assert!(headers.len() >= headers1.len());
        let headers = tf2.chainstate.filter_already_existing_blocks(headers).unwrap();
        assert_eq!(headers, headers1);
    });
}

// Try to use headers that aren't attached to the chain.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn filter_already_existing_blocks_detached_headers(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let mut tf1 = TestFramework::builder(&mut rng).build();
        let mut tf2 = TestFramework::builder(&mut rng).build();

        let mut prev_id = tf1.genesis().get_id().into();
        for _ in 0..rng.gen_range(8..16) {
            let block = tf1
                .make_block_builder()
                .with_parent(prev_id)
                .add_test_transaction_from_best_block(&mut rng)
                .build();
            prev_id = block.get_id().into();
            tf1.process_block(block.clone(), BlockSource::Local).unwrap();
            tf2.process_block(block.clone(), BlockSource::Local).unwrap();
            assert_eq!(tf1.best_block_id(), tf2.best_block_id());
        }

        let mut headers = Vec::new();
        for _ in 0..rng.gen_range(3..10) {
            let block = tf2
                .make_block_builder()
                .with_parent(prev_id)
                .add_test_transaction_with_parent(prev_id, &mut rng)
                .build();
            prev_id = block.get_id().into();
            headers.push(block.header().clone());
            tf2.process_block(block, BlockSource::Local).unwrap();
        }

        let filtered_headers = tf1.chainstate.filter_already_existing_blocks(headers[1..].to_vec());
        assert_eq!(
            filtered_headers,
            Err(ChainstateError::FailedToReadProperty(
                PropertyQueryError::BlockNotFound(Id::new(headers[1].prev_block_id().get()))
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn initial_block_download(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chainstate_config(ChainstateConfig {
                max_db_commit_attempts: Default::default(),
                max_orphan_blocks: Default::default(),
                min_max_bootstrap_import_buffer_sizes: Default::default(),
                tx_index_enabled: Default::default(),
                max_tip_age: Duration::from_secs(1).into(),
            })
            .build();

        // Only genesis block, so is_initial_block_download should return true.
        assert!(tf.chainstate.is_initial_block_download().unwrap());

        // Create a block with an "old" timestamp.
        let now = tf.current_time();
        tf.progress_time_seconds_since_epoch(3);
        tf.make_block_builder()
            .with_timestamp(BlockTimestamp::from_duration_since_epoch(now))
            .build_and_process()
            .unwrap();
        assert!(tf.chainstate.is_initial_block_download().unwrap());

        // Create a block with fresh timestamp.
        tf.make_block_builder().build_and_process().unwrap();
        assert!(!tf.chainstate.is_initial_block_download().unwrap());

        // Add one more block.
        tf.make_block_builder().build_and_process().unwrap();
        assert!(!tf.chainstate.is_initial_block_download().unwrap());
    });
}

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

use chainstate::{BlockSource, ChainstateConfig, ChainstateError};
use chainstate_test_framework::TestFramework;
use chainstate_types::PropertyQueryError;
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp},
        GenBlock,
    },
    primitives::{BlockDistance, BlockHeight, Id, Idable, H256},
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
            assert_eq!(
                locator.len(),
                blocks.next_power_of_two().trailing_zeros() as usize + 1
            );

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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_locator_from_height(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut btf = TestFramework::builder(&mut rng).build();

        let blocks = rng.gen_range(1001..2000);
        btf.create_chain(&btf.genesis().get_id().into(), blocks, &mut rng).unwrap();

        for _ in 0..8 {
            let height = rng.gen_range(1000..blocks) as u64;

            // Check the locator length.
            let locator = btf.chainstate.get_locator_from_height(height.into()).unwrap();
            assert_eq!(
                locator.len(),
                (height + 1).next_power_of_two().trailing_zeros() as usize + 1
            );

            // Check the locator headers.
            assert_eq!(
                &locator[0],
                &btf.chainstate.get_block_id_from_height(&height.into()).unwrap().unwrap()
            );
            for (i, header) in locator.iter().skip(1).enumerate() {
                let idx = BlockHeight::from(height) - BlockDistance::new(2i64.pow(i as u32));
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
        let header_limit = rng.gen_range(1500..=2000);
        let headers_count = rng.gen_range(1000..header_limit);
        let blocks_count = rng.gen_range(1000..2000);

        let mut tf = TestFramework::builder(&mut rng).build();
        let mut last_block_id = tf.genesis().get_id().into();
        last_block_id = tf.create_chain(&last_block_id, blocks_count, &mut rng).unwrap();

        // The locator is from this exact chain, so `get_headers` should return an empty sequence.
        let locator = tf.chainstate.get_locator().unwrap();
        assert_eq!(
            tf.chainstate.get_headers(locator.clone(), header_limit).unwrap(),
            vec![],
        );

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

        let headers = tf.chainstate.get_headers(locator.clone(), header_limit).unwrap();
        assert_eq!(headers, expected);
        // Because both the locator and chainstate are tracking the same chain, the first header of
        // the locator is always the parent of the first new block.
        assert_eq!(expected[0].prev_block_id(), &locator[0]);

        // Produce more blocks than `HEADER_LIMIT`, so get_headers is truncated.
        tf.create_chain(&last_block_id, header_limit - expected.len(), &mut rng)
            .unwrap();
        let headers = tf.chainstate.get_headers(locator, header_limit).unwrap();
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

        let header_count_limit = rng.gen_range(chain_length..chain_length * 2);
        let headers = btf.chainstate.get_headers(locator_1, header_count_limit).unwrap();
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
        let common_height = rng.gen_range(100..1000);

        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::new(common::chain::config::ChainType::Regtest)
                    .net_upgrades(common::chain::NetUpgrades::unit_tests())
                    .max_depth_for_reorg(BlockDistance::new(5000))
                    .build(),
            )
            .build();
        let common_block_id =
            tf.create_chain(&tf.genesis().get_id().into(), common_height, &mut rng).unwrap();

        tf.create_chain(&common_block_id, rng.gen_range(100..250), &mut rng).unwrap();
        let locator = tf.chainstate.get_locator().unwrap();
        tf.create_chain(&common_block_id, rng.gen_range(250..500), &mut rng).unwrap();

        let headers = tf.chainstate.get_headers(locator, 2000).unwrap();
        let id = headers[0].prev_block_id();
        assert!(tf.block_index(id).block_height() <= BlockHeight::new(common_height as u64));
    });
}

fn get_headers_for_ids(tf: &TestFramework, ids: &[Id<GenBlock>]) -> Vec<SignedBlockHeader> {
    let mut result = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.classify(tf.chainstate.get_chain_config()).chain_block_id().unwrap();
        let block_index = tf.chainstate.get_block_index(&id).unwrap().unwrap();
        result.push(block_index.block_header().clone());
    }
    result
}

// Call get_headers_since_fork_point on a block from the main chain.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_since_fork_point_for_main_chain_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let ids = tf
            .create_chain_return_ids(&genesis_id.into(), rng.gen_range(100..250), &mut rng)
            .unwrap();

        let idx = rng.gen_range((ids.len() / 4)..(3 * ids.len() / 4));
        let headers = tf.chainstate.get_headers_since_fork_point(&ids[idx], 1_000_000).unwrap();
        let expected_headers = get_headers_for_ids(&tf, &ids[idx + 1..]);
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_headers_since_fork_point on a block from the main chain, this time with a small limit.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_since_fork_point_for_main_chain_block_with_limit(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let ids = tf
            .create_chain_return_ids(&genesis_id.into(), rng.gen_range(100..250), &mut rng)
            .unwrap();

        let idx = rng.gen_range((ids.len() / 4)..(3 * ids.len() / 4));
        let limit = ids.len() / 8;
        let headers = tf.chainstate.get_headers_since_fork_point(&ids[idx], limit).unwrap();
        let expected_headers = get_headers_for_ids(&tf, &ids[idx + 1..idx + limit + 1]);
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_headers_since_fork_point on a block from a stale chain.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_since_fork_point_for_stale_chain_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        // Main chain length without genesis.
        let mc_len = rng.gen_range(100..250);
        let fork_point = rng.gen_range((mc_len / 4)..(mc_len / 2));
        // Stale chain length (it's at least mc_len/8)
        let sc_len = rng.gen_range(((mc_len - fork_point) / 4)..(3 * (mc_len - fork_point) / 4));

        let mc_ids = tf.create_chain_return_ids(&genesis_id.into(), mc_len, &mut rng).unwrap();
        let sc_ids = tf.create_chain_return_ids(&mc_ids[fork_point], sc_len, &mut rng).unwrap();

        let idx = rng.gen_range((sc_ids.len() / 4)..(3 * sc_ids.len() / 4));
        let headers = tf.chainstate.get_headers_since_fork_point(&sc_ids[idx], 1_000_000).unwrap();
        let expected_headers = get_headers_for_ids(&tf, &mc_ids[fork_point + 1..]);
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_headers_since_fork_point on a block from a stale chain, this time with a small limit.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_since_fork_point_for_stale_chain_block_with_limit(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        // Main chain length without genesis.
        let mc_len = rng.gen_range(100..250);
        let fork_point = rng.gen_range((mc_len / 4)..(mc_len / 2));
        // Stale chain length (it's at least mc_len/8)
        let sc_len = rng.gen_range(((mc_len - fork_point) / 4)..(3 * (mc_len - fork_point) / 4));

        let mc_ids = tf.create_chain_return_ids(&genesis_id.into(), mc_len, &mut rng).unwrap();
        let sc_ids = tf.create_chain_return_ids(&mc_ids[fork_point], sc_len, &mut rng).unwrap();

        let idx = rng.gen_range((sc_ids.len() / 4)..(3 * sc_ids.len() / 4));
        let limit = mc_len / 8;
        let headers = tf.chainstate.get_headers_since_fork_point(&sc_ids[idx], limit).unwrap();
        let expected_headers =
            get_headers_for_ids(&tf, &mc_ids[fork_point + 1..fork_point + limit + 1]);
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_headers_since_fork_point on a block which doesn't exist in the chainstate.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_headers_since_fork_point_for_non_existent_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        tf.create_chain(&genesis_id.into(), rng.gen_range(100..250), &mut rng).unwrap();

        let bogus_block_id = Id::<GenBlock>::new(H256([0x23; 32]));
        let error = tf
            .chainstate
            .get_headers_since_fork_point(&bogus_block_id, 1_000_000)
            .unwrap_err();
        assert_eq!(
            error,
            ChainstateError::FailedToReadProperty(PropertyQueryError::BlockIndexNotFound(
                bogus_block_id
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_reorg_past_limit(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::new(common::chain::config::ChainType::Regtest)
                    .net_upgrades(common::chain::NetUpgrades::unit_tests())
                    .max_depth_for_reorg(BlockDistance::new(1))
                    .build(),
            )
            .build();
        let common_block_id = tf.best_block_id();

        tf.create_chain(&common_block_id, 2, &mut rng).unwrap();
        let res = tf.create_chain(&common_block_id, 1, &mut rng).unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::AttemptedToAddBlockBeforeReorgLimit(
                    BlockHeight::new(0),
                    BlockHeight::new(2),
                    BlockHeight::new(1)
                )
            ))
        )
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn otry_reorg_past_limit_in_fork(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::new(common::chain::config::ChainType::Regtest)
                    .net_upgrades(common::chain::NetUpgrades::unit_tests())
                    .max_depth_for_reorg(BlockDistance::new(2))
                    .build(),
            )
            .build();
        let common_block_id = tf.best_block_id();

        let tip_id = tf.create_chain(&common_block_id, 2, &mut rng).unwrap();
        let fork_tip_id = tf.create_chain(&common_block_id, 1, &mut rng).unwrap();

        // advance the mainchain
        tf.create_chain(&tip_id, 1, &mut rng).unwrap();

        // try add block in fork
        let res = tf.create_chain(&fork_tip_id, 1, &mut rng).unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::AttemptedToAddBlockBeforeReorgLimit(
                    BlockHeight::new(0),
                    BlockHeight::new(3),
                    BlockHeight::new(1)
                )
            ))
        )
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

        let header_count_limit = rng.gen_range(1000..3000);
        let locator = tf1.chainstate.get_locator().unwrap();
        let headers = tf2.chainstate.get_headers(locator, header_count_limit).unwrap();
        let id = *headers[0].prev_block_id();
        tf1.block_index(&id); // This panics if the ID is not found

        let locator = tf2.chainstate.get_locator().unwrap();
        let headers = tf1.chainstate.get_headers(locator, header_count_limit).unwrap();
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
        let header_count_limit = rng.gen_range(1000..3000);
        let headers = tf2.chainstate.get_headers(locator, header_count_limit).unwrap();
        assert!(headers.len() >= headers2.len());
        let headers = tf1.chainstate.filter_already_existing_blocks(headers).unwrap();
        assert_eq!(headers, headers2);

        let locator = tf2.chainstate.get_locator().unwrap();
        let headers = tf1.chainstate.get_headers(locator, header_count_limit).unwrap();
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
            .with_initial_time_since_genesis(2)
            .build();

        // We are two seconds after genesis timestamp, so in the IBD state
        assert!(tf.chainstate.is_initial_block_download());

        // Create a block with an "old" timestamp.
        let now = tf.current_time();
        tf.progress_time_seconds_since_epoch(3);
        tf.make_block_builder()
            .with_timestamp(BlockTimestamp::from_duration_since_epoch(now))
            .build_and_process()
            .unwrap();
        assert!(tf.chainstate.is_initial_block_download());

        // Create a block with fresh timestamp.
        tf.make_block_builder().build_and_process().unwrap();
        assert!(!tf.chainstate.is_initial_block_download());

        // Add one more block.
        tf.make_block_builder().build_and_process().unwrap();
        assert!(!tf.chainstate.is_initial_block_download());

        // Check that receiving an "old" block does not revert `is_initial_block_download` back
        tf.progress_time_seconds_since_epoch(5);
        let now = tf.current_time();
        let block = tf
            .make_block_builder()
            .with_timestamp(BlockTimestamp::from_duration_since_epoch(now))
            .build();
        tf.progress_time_seconds_since_epoch(10);
        tf.process_block(block, BlockSource::Local).unwrap();
        assert!(!tf.chainstate.is_initial_block_download());
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn header_check_for_orphan(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chainstate_config(ChainstateConfig {
                max_db_commit_attempts: Default::default(),
                max_orphan_blocks: Default::default(),
                min_max_bootstrap_import_buffer_sizes: Default::default(),
                tx_index_enabled: Default::default(),
                max_tip_age: Default::default(),
            })
            .build();

        tf.progress_time_seconds_since_epoch(3);
        let block = tf.make_block_builder().make_orphan(&mut rng).build();
        let block_id = block.get_id();

        let err = tf.chainstate.preliminary_header_check(block.header().clone()).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::PrevBlockNotFound(
                    block.prev_block_id(),
                    block.get_id(),
                ),
            ))
        );

        let err = tf.chainstate.preliminary_block_check(block.clone()).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::PrevBlockNotFound(
                    block.prev_block_id(),
                    block.get_id(),
                ),
            ))
        );

        let err = tf.chainstate.process_block(block, BlockSource::Peer).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::ProcessBlockError(
                chainstate::BlockError::PrevBlockNotFoundForNewBlock(block_id)
            )
        );
    });
}

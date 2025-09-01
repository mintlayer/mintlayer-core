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

use std::{collections::BTreeMap, iter, num::NonZeroUsize, time::Duration};

use rstest::rstest;

use chainstate::{BlockSource, ChainstateConfig, ChainstateError, CheckBlockError};
use chainstate_test_framework::TestFramework;
use chainstate_types::PropertyQueryError;
use common::{
    chain::{
        self,
        block::{signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp},
        GenBlock,
    },
    primitives::{BlockDistance, BlockHeight, Id, Idable, H256},
    Uint256,
};
use randomness::Rng;
use test_utils::random::{make_seedable_rng, Seed};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn process_a_trivial_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut btf = TestFramework::builder(&mut rng).build();
    btf.make_block_builder().build_and_process(&mut rng).unwrap();
}

// Generate some blocks and check that a locator is of expected length.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_locator(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut btf = TestFramework::builder(&mut rng)
            // With the heavy checks enabled, this test takes several minutes to complete in debug builds.
            .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
            .build();

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
        let mut btf = TestFramework::builder(&mut rng)
            // With the heavy checks enabled, this test takes over a minute to complete in debug builds.
            .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
            .build();

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
fn get_mainchain_headers_by_locator(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let header_limit = rng.gen_range(1500..=2000);
        let headers_count = rng.gen_range(1000..header_limit);
        let blocks_count = rng.gen_range(1000..2000);

        let mut tf = TestFramework::builder(&mut rng)
            // With the heavy checks enabled, this test takes a few minutes to complete in debug builds.
            .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
            .build();
        let mut last_block_id = tf.genesis().get_id().into();
        last_block_id = tf.create_chain(&last_block_id, blocks_count, &mut rng).unwrap();

        // The locator is from this exact chain, so get_mainchain_headers_by_locator
        // should return an empty sequence.
        let locator = tf.chainstate.get_locator().unwrap();
        assert_eq!(
            tf.chainstate.get_mainchain_headers_by_locator(&locator, header_limit).unwrap(),
            vec![],
        );

        // Produce more blocks. Now get_mainchain_headers_by_locator should return these blocks.
        let expected: Vec<_> = iter::from_fn(|| {
            let block = tf
                .make_block_builder()
                .with_parent(last_block_id)
                .add_test_transaction_from_best_block(&mut rng)
                .build(&mut rng);
            last_block_id = block.get_id().into();
            let header = block.header().clone();
            tf.process_block(block, BlockSource::Peer).unwrap().unwrap();
            Some(header)
        })
        .take(headers_count)
        .collect();

        let headers =
            tf.chainstate.get_mainchain_headers_by_locator(&locator, header_limit).unwrap();
        assert_eq!(headers, expected);
        // Because both the locator and chainstate are tracking the same chain, the first header of
        // the locator is always the parent of the first new block.
        assert_eq!(expected[0].prev_block_id(), &locator[0]);

        // Produce more blocks than header_limit, so get_mainchain_headers_by_locator is truncated.
        tf.create_chain(&last_block_id, header_limit - expected.len(), &mut rng)
            .unwrap();
        let headers =
            tf.chainstate.get_mainchain_headers_by_locator(&locator, header_limit).unwrap();
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

        let mut btf = TestFramework::builder(&mut rng)
            // With the heavy checks enabled, this test takes over a minute to complete in debug builds.
            .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
            .build();
        let genesis_id: Id<GenBlock> = btf.genesis().get_id().into();

        btf.create_chain(&genesis_id, rng.gen_range(64..128), &mut rng).unwrap();
        let locator_1 = btf.chainstate.get_locator().unwrap();

        let chain_length = rng.gen_range(1200..2000);
        btf.create_chain(&genesis_id, chain_length, &mut rng).unwrap();
        let locator_2 = btf.chainstate.get_locator().unwrap();
        assert_ne!(locator_1, locator_2);
        assert!(locator_1.len() < locator_2.len());

        let header_count_limit = rng.gen_range(chain_length..chain_length * 2);
        let headers = btf
            .chainstate
            .get_mainchain_headers_by_locator(&locator_1, header_count_limit)
            .unwrap();
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
                    .consensus_upgrades(common::chain::NetUpgrades::unit_tests())
                    .max_depth_for_reorg(BlockDistance::new(5000))
                    .build(),
            )
            // The heavy checks don't make much sense for this test and it's relatively lengthy,
            // so we disable them.
            .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
            .build();
        let common_block_id =
            tf.create_chain(&tf.genesis().get_id().into(), common_height, &mut rng).unwrap();

        tf.create_chain(&common_block_id, rng.gen_range(100..250), &mut rng).unwrap();
        let locator = tf.chainstate.get_locator().unwrap();
        tf.create_chain(&common_block_id, rng.gen_range(250..500), &mut rng).unwrap();

        let headers = tf.chainstate.get_mainchain_headers_by_locator(&locator, 2000).unwrap();
        let id = headers[0].prev_block_id();
        assert!(tf.gen_block_index(id).block_height() <= BlockHeight::new(common_height as u64));
    });
}

fn get_headers_for_ids(tf: &TestFramework, ids: &[Id<GenBlock>]) -> Vec<SignedBlockHeader> {
    let mut result = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.classify(tf.chainstate.get_chain_config()).chain_block_id().unwrap();
        let block_index = tf.block_index(&id);
        result.push(block_index.block_header().clone());
    }
    result
}

// Call get_mainchain_headers_since_latest_fork_point on blocks from the main chain.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_mainchain_headers_since_latest_fork_point_for_mainchain_blocks(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let ids = tf.create_chain_return_ids(&genesis_id.into(), 100, &mut rng).unwrap();

        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(&[ids[50], ids[60]], 1_000_000)
            .unwrap();
        let expected_headers = get_headers_for_ids(&tf, &ids[61..]);
        assert_eq!(&headers, &expected_headers);

        // Reverse the order of ids in the slice, the result should stay the same.
        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(&[ids[60], ids[50]], 1_000_000)
            .unwrap();
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_mainchain_headers_since_latest_fork_point on blocks from the main chain,
// this time with a small limit.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_mainchain_headers_since_latest_fork_point_for_mainchain_blocks_with_limit(
    #[case] seed: Seed,
) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let ids = tf.create_chain_return_ids(&genesis_id.into(), 100, &mut rng).unwrap();

        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(&[ids[50], ids[60]], 20)
            .unwrap();
        let expected_headers = get_headers_for_ids(&tf, &ids[61..81]);
        assert_eq!(&headers, &expected_headers);

        // Reverse the order of ids in the slice, the result should stay the same.
        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(&[ids[60], ids[50]], 20)
            .unwrap();
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_mainchain_headers_since_latest_fork_point on blocks from stale chains.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_mainchain_headers_since_latest_fork_point_for_stale_chain_blocks(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let mc_ids = tf.create_chain_return_ids(&genesis_id.into(), 100, &mut rng).unwrap();
        let sc1_ids = tf.create_chain_return_ids(&mc_ids[20], 40, &mut rng).unwrap();
        let sc2_ids = tf.create_chain_return_ids(&mc_ids[30], 40, &mut rng).unwrap();

        // Use ids from both stale chains
        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(
                &[sc1_ids[10], sc1_ids[20], sc2_ids[10], sc2_ids[20]],
                1_000_000,
            )
            .unwrap();
        // The earliest fork point should be selected
        let expected_headers = get_headers_for_ids(&tf, &mc_ids[31..]);
        assert_eq!(&headers, &expected_headers);

        // Rearrange the ids in the slice, the result should stay the same.
        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(
                &[sc2_ids[20], sc2_ids[10], sc1_ids[20], sc1_ids[10]],
                1_000_000,
            )
            .unwrap();
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_mainchain_headers_since_latest_fork_point on blocks from a stale chain, this time with a small limit.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_mainchain_headers_since_latest_fork_point_for_stale_chain_blocks_with_limit(
    #[case] seed: Seed,
) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        let mc_ids = tf.create_chain_return_ids(&genesis_id.into(), 100, &mut rng).unwrap();
        let sc1_ids = tf.create_chain_return_ids(&mc_ids[20], 40, &mut rng).unwrap();
        let sc2_ids = tf.create_chain_return_ids(&mc_ids[30], 40, &mut rng).unwrap();

        // Use ids from both stale chains
        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(
                &[sc1_ids[10], sc1_ids[20], sc2_ids[10], sc2_ids[20]],
                20,
            )
            .unwrap();
        // The earliest fork point should be selected
        let expected_headers = get_headers_for_ids(&tf, &mc_ids[31..51]);
        assert_eq!(&headers, &expected_headers);

        // Rearrange the ids in the slice, the result should stay the same.
        let headers = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(
                &[sc2_ids[20], sc2_ids[10], sc1_ids[20], sc1_ids[10]],
                20,
            )
            .unwrap();
        assert_eq!(&headers, &expected_headers);
    });
}

// Call get_mainchain_headers_since_latest_fork_point on a block which doesn't exist in the chainstate.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_mainchain_headers_since_latest_fork_point_for_non_existent_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        tf.create_chain(&genesis_id.into(), 100, &mut rng).unwrap();

        let bogus_block_id = Id::<GenBlock>::new(H256([0x23; 32]));
        let error = tf
            .chainstate
            .get_mainchain_headers_since_latest_fork_point(&[bogus_block_id], 1_000_000)
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
                    .consensus_upgrades(common::chain::NetUpgrades::unit_tests())
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
                    .consensus_upgrades(common::chain::NetUpgrades::unit_tests())
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
                .build(&mut rng);
            prev_id = block.get_id().into();
            tf1.process_block(block.clone(), BlockSource::Local).unwrap();
            tf2.process_block(block.clone(), BlockSource::Local).unwrap();
            assert_eq!(tf1.best_block_id(), tf2.best_block_id());
        }

        tf1.create_chain(&prev_id, rng.gen_range(32..256), &mut rng).unwrap();
        tf2.create_chain(&prev_id, rng.gen_range(256..512), &mut rng).unwrap();

        let header_count_limit = rng.gen_range(1000..3000);
        let locator = tf1.chainstate.get_locator().unwrap();
        let headers = tf2
            .chainstate
            .get_mainchain_headers_by_locator(&locator, header_count_limit)
            .unwrap();
        let id = *headers[0].prev_block_id();
        tf1.gen_block_index(&id); // This panics if the ID is not found

        let locator = tf2.chainstate.get_locator().unwrap();
        let headers = tf1
            .chainstate
            .get_mainchain_headers_by_locator(&locator, header_count_limit)
            .unwrap();
        let id = *headers[0].prev_block_id();
        tf2.gen_block_index(&id); // This panics if the ID is not found
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn split_off_leading_known_headers(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let mut tf1 = TestFramework::builder(&mut rng).build();
        let mut tf2 = TestFramework::builder(&mut rng).build();

        // Create 10 blocks and add them to both chains.
        let common_blocks_headers = {
            let mut prev1_id = tf1.genesis().get_id().into();
            let mut common_blocks_headers = Vec::new();
            for _ in 0..10 {
                let block = tf1
                    .make_block_builder()
                    .with_parent(prev1_id)
                    .add_test_transaction_from_best_block(&mut rng)
                    .build(&mut rng);
                prev1_id = block.get_id().into();
                tf1.process_block(block.clone(), BlockSource::Local).unwrap();
                tf2.process_block(block.clone(), BlockSource::Local).unwrap();
                assert_eq!(tf1.best_block_id(), tf2.best_block_id());
                common_blocks_headers.push(block.header().clone());
            }

            common_blocks_headers
        };
        let last_common_block_id = common_blocks_headers.last().unwrap().block_id();

        // Create some blocks on tf1 specifically.
        let chain1_specific_block_ids =
            tf1.create_chain_return_ids(&last_common_block_id.into(), 10, &mut rng).unwrap();
        let chain1_specific_block_headers = get_headers_for_ids(&tf1, &chain1_specific_block_ids);

        // Create some blocks on tf2; they will serve as "unknown" blocks for tf1.
        let chain2_specific_block_ids =
            tf2.create_chain_return_ids(&last_common_block_id.into(), 10, &mut rng).unwrap();
        let chain2_specific_block_headers = get_headers_for_ids(&tf2, &chain2_specific_block_ids);

        // All headers are known.
        let input_headers =
            [&common_blocks_headers[1..3], &chain1_specific_block_headers[1..3]].concat();
        let (known_headers, unknown_headers) =
            tf1.chainstate.split_off_leading_known_headers(input_headers.clone()).unwrap();
        assert_eq!(known_headers, input_headers);
        assert_eq!(unknown_headers, Vec::new());

        // Some headers are known.
        let input_headers =
            [&common_blocks_headers[1..3], &chain2_specific_block_headers[1..3]].concat();
        let (known_headers, unknown_headers) =
            tf1.chainstate.split_off_leading_known_headers(input_headers).unwrap();
        assert_eq!(known_headers, common_blocks_headers[1..3]);
        assert_eq!(unknown_headers, chain2_specific_block_headers[1..3]);

        // All headers are unknown.
        let input_headers = [&chain2_specific_block_headers[1..3]].concat();
        let (known_headers, unknown_headers) =
            tf1.chainstate.split_off_leading_known_headers(input_headers).unwrap();
        assert_eq!(known_headers, Vec::new());
        assert_eq!(unknown_headers, chain2_specific_block_headers[1..3]);

        // Some known blocks come after the unknown ones - only the leading known ones
        // are split off.
        let input_headers = [
            &common_blocks_headers[1..3],
            &chain2_specific_block_headers[1..3],
            &common_blocks_headers[1..3],
        ]
        .concat();
        let (known_headers, unknown_headers) =
            tf1.chainstate.split_off_leading_known_headers(input_headers).unwrap();
        assert_eq!(known_headers, common_blocks_headers[1..3]);
        assert_eq!(
            unknown_headers,
            [&chain2_specific_block_headers[1..3], &common_blocks_headers[1..3]].concat()
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
                max_tip_age: Duration::from_secs(1).into(),
                enable_heavy_checks: Some(true),
                allow_checkpoints_mismatch: Default::default(),
            })
            .with_initial_time_since_genesis(2)
            .build();

        // We are two seconds after genesis timestamp, so in the IBD state
        assert!(tf.chainstate.is_initial_block_download());

        // Create a block with an "old" timestamp.
        let now = tf.current_time();
        tf.progress_time_seconds_since_epoch(3);
        tf.make_block_builder()
            .with_timestamp(BlockTimestamp::from_time(now))
            .build_and_process(&mut rng)
            .unwrap();
        assert!(tf.chainstate.is_initial_block_download());

        // Create a block with fresh timestamp.
        tf.make_block_builder().build_and_process(&mut rng).unwrap();
        assert!(!tf.chainstate.is_initial_block_download());

        // Add one more block.
        tf.make_block_builder().build_and_process(&mut rng).unwrap();
        assert!(!tf.chainstate.is_initial_block_download());

        // Check that receiving an "old" block does not revert `is_initial_block_download` back
        tf.progress_time_seconds_since_epoch(5);
        let now = tf.current_time();
        let block = tf
            .make_block_builder()
            .with_timestamp(BlockTimestamp::from_time(now))
            .build(&mut rng);
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
        let mut tf = TestFramework::builder(&mut rng).build();

        tf.progress_time_seconds_since_epoch(3);
        let block = tf.make_block_builder().make_orphan(&mut rng).build(&mut rng);
        let block_id = block.get_id();

        let err = tf
            .chainstate
            .preliminary_headers_check(std::slice::from_ref(block.header()))
            .unwrap_err();
        assert_eq!(
            err,
            ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::ParentBlockMissing {
                    block_id: block.get_id(),
                    parent_block_id: block.prev_block_id(),
                },
            ))
        );

        let err = tf.chainstate.preliminary_block_check(block.clone()).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::ParentBlockMissing {
                    block_id: block.get_id(),
                    parent_block_id: block.prev_block_id(),
                },
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

// Ensure that preliminary_headers_check succeeds when all headers satisfy the checkpoints
// and fails when some of them do not.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn headers_check_with_checkpoints(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let (parent_block, block_headers) = {
            let mut tf = TestFramework::builder(&mut rng).build();
            let parent_block_id =
                tf.create_chain_return_ids(&tf.genesis().get_id().into(), 1, &mut rng).unwrap()[0];
            let parent_block = tf.block(tf.to_chain_block_id(&parent_block_id));
            let ids =
                tf.create_chain_return_ids(&parent_block.get_id().into(), 10, &mut rng).unwrap();
            let block_headers = ids
                .iter()
                .map(|id| {
                    let id = tf.to_chain_block_id(id);
                    tf.chainstate.get_block_header(id).unwrap().unwrap()
                })
                .collect::<Vec<_>>();
            (parent_block, block_headers)
        };

        // All blocks are checkpointed; all checkpoints are satisfied.
        {
            let checkpoints = block_headers
                .iter()
                .enumerate()
                .map(|(idx, header)| (BlockHeight::new(idx as u64 + 2), header.block_id().into()))
                .collect::<BTreeMap<_, _>>();

            let mut tf = TestFramework::builder(&mut rng)
                .with_chain_config(
                    chain::config::create_unit_test_config_builder()
                        .checkpoints(checkpoints)
                        .build(),
                )
                .build();
            tf.process_block(parent_block.clone(), BlockSource::Local).unwrap();

            tf.chainstate.preliminary_headers_check(&block_headers).unwrap();
        }

        // A few blocks are checkpointed; all checkpoints are satisfied.
        {
            let checkpoints = [
                (BlockHeight::new(3), block_headers[1].block_id().into()),
                (BlockHeight::new(7), block_headers[5].block_id().into()),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>();

            let mut tf = TestFramework::builder(&mut rng)
                .with_chain_config(
                    chain::config::create_unit_test_config_builder()
                        .checkpoints(checkpoints)
                        .build(),
                )
                .build();
            tf.process_block(parent_block.clone(), BlockSource::Local).unwrap();

            tf.chainstate.preliminary_headers_check(&block_headers).unwrap();
        }

        // All blocks are checkpointed; some checkpoints are not satisfied.
        {
            let mut checkpoints = block_headers
                .iter()
                .enumerate()
                .map(|(idx, header)| (BlockHeight::new(idx as u64 + 2), header.block_id().into()))
                .collect::<BTreeMap<_, _>>();
            let bad_checkpoint_height = BlockHeight::new(5);
            let good_block_id = Id::new(Uint256::from_u64(12345).into());
            let bad_block_id = checkpoints.insert(bad_checkpoint_height, good_block_id).unwrap();

            let mut tf = TestFramework::builder(&mut rng)
                .with_chain_config(
                    chain::config::create_unit_test_config_builder()
                        .checkpoints(checkpoints)
                        .build(),
                )
                .build();
            tf.process_block(parent_block.clone(), BlockSource::Local).unwrap();

            let err = tf.chainstate.preliminary_headers_check(&block_headers).unwrap_err();
            assert_eq!(
                err,
                ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                    CheckBlockError::CheckpointMismatch {
                        height: bad_checkpoint_height,
                        expected: good_block_id,
                        given: bad_block_id
                    }
                ))
            );
        }

        // A few blocks are checkpointed; some checkpoints are not satisfied.
        {
            let good_block_id = Id::new(Uint256::from_u64(12345).into());
            let bad_block_id = block_headers[5].block_id().into();
            let bad_checkpoint_height = BlockHeight::new(7);
            let checkpoints = [
                (BlockHeight::new(3), block_headers[1].block_id().into()),
                (bad_checkpoint_height, good_block_id),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>();

            let mut tf = TestFramework::builder(&mut rng)
                .with_chain_config(
                    chain::config::create_unit_test_config_builder()
                        .checkpoints(checkpoints)
                        .build(),
                )
                .build();
            tf.process_block(parent_block.clone(), BlockSource::Local).unwrap();

            let err = tf.chainstate.preliminary_headers_check(&block_headers).unwrap_err();
            assert_eq!(
                err,
                ChainstateError::ProcessBlockError(chainstate::BlockError::CheckBlockFailed(
                    CheckBlockError::CheckpointMismatch {
                        height: bad_checkpoint_height,
                        expected: good_block_id,
                        given: bad_block_id
                    }
                ))
            );
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_block_ids_as_checkpoints(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut btf = TestFramework::builder(&mut rng).build();

        let locator = btf.chainstate.get_locator().unwrap();
        assert_eq!(locator.len(), 1);
        assert_eq!(&locator[0], &btf.genesis().get_id());

        let genesis_id = btf.genesis().get_id().into();
        let block_ids = btf.create_chain_return_ids(&genesis_id, 100, &mut rng).unwrap();

        let start = 10.into();
        let end = 0.into();
        let bad_range_error = btf
            .chainstate
            .get_block_ids_as_checkpoints(start, end, NonZeroUsize::new(1).unwrap())
            .unwrap_err();
        assert_eq!(
            bad_range_error,
            ChainstateError::FailedToReadProperty(PropertyQueryError::InvalidBlockHeightRange {
                start,
                end,
            })
        );

        let result = btf
            .chainstate
            .get_block_ids_as_checkpoints(0.into(), 5.into(), NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(
            result,
            [
                (0.into(), genesis_id),
                (1.into(), block_ids[0]),
                (2.into(), block_ids[1]),
                (3.into(), block_ids[2]),
                (4.into(), block_ids[3]),
            ]
        );

        let result = btf
            .chainstate
            .get_block_ids_as_checkpoints(0.into(), 1000000.into(), NonZeroUsize::new(20).unwrap())
            .unwrap();
        assert_eq!(
            result,
            [
                (0.into(), genesis_id),
                (20.into(), block_ids[19]),
                (40.into(), block_ids[39]),
                (60.into(), block_ids[59]),
                (80.into(), block_ids[79]),
                (100.into(), block_ids[99]),
            ]
        );

        let result = btf
            .chainstate
            .get_block_ids_as_checkpoints(2.into(), 10.into(), NonZeroUsize::new(3).unwrap())
            .unwrap();
        assert_eq!(
            result,
            [(2.into(), block_ids[1]), (5.into(), block_ids[4]), (8.into(), block_ids[7]),]
        );

        let result = btf
            .chainstate
            .get_block_ids_as_checkpoints(10.into(), 10.into(), NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(result, []);

        let result = btf
            .chainstate
            .get_block_ids_as_checkpoints(
                1000000.into(),
                2000000.into(),
                NonZeroUsize::new(1).unwrap(),
            )
            .unwrap();
        assert_eq!(result, []);
    });
}

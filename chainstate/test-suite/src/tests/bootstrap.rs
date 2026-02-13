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

use std::{
    collections::{BTreeMap, BTreeSet},
    io::BufWriter,
};

use itertools::Itertools as _;
use rstest::rstest;
use strum::IntoEnumIterator;

use chainstate::{
    chainstate_interface::ChainstateInterface, BootstrapError, ChainstateConfig, ChainstateError,
};
use chainstate_storage::BlockchainStorage;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{self, config::ChainType, Block, ChainConfig, Destination, NetUpgrades},
    primitives::{Id, Idable},
};
use logging::log;
use rand::{seq::IteratorRandom as _, CryptoRng, Rng};
use serialization::Encode as _;
use test_utils::random::{gen_random_bytes, make_seedable_rng, Seed};

/// Ensure that the blocks vector put blocks in order with height in the blockchain
fn check_height_order(blocks: &[Id<Block>], tf: &TestFramework) {
    let mut last_height = 0;
    for block_id in blocks {
        let height = tf.block_index(block_id).block_height();
        let current_height: u64 = height.into();
        assert!(current_height >= last_height);
        last_height = current_height;
    }
}

const EXPECTED_MAGIC_BYTES: &str = "MLBTSTRP";

fn make_header_data(chain_config: &ChainConfig, version: u32, blocks_count: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(EXPECTED_MAGIC_BYTES.as_bytes());
    data.extend_from_slice(&chain_config.magic_bytes().bytes());
    data.extend_from_slice(&version.to_le_bytes());
    data.extend_from_slice(&blocks_count.to_le_bytes());

    data
}

fn append_block_data_for_v0(dest: &mut Vec<u8>, encoded_block_data: &[u8]) {
    dest.extend_from_slice(&(encoded_block_data.len() as u32).to_le_bytes());
    dest.extend_from_slice(encoded_block_data);
}

fn gen_blocks(
    chain_config: ChainConfig,
    blocks_count: usize,
    mut rng: impl Rng + CryptoRng,
) -> Vec<Block> {
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    let genesis_id = tf.genesis().get_id();
    tf.create_chain(&genesis_id.into(), blocks_count, &mut rng).unwrap();

    tf.chainstate
        .get_block_id_tree_as_list()
        .unwrap()
        .iter()
        .map(|block_id| tf.chainstate.get_block(block_id).unwrap().unwrap())
        .collect_vec()
}

fn export_to_vec(tf: &TestFramework, with_stale_blocks: bool) -> Vec<u8> {
    let mut write_buffer = Vec::new();

    let writer: BufWriter<Box<dyn std::io::Write + Send>> =
        BufWriter::new(Box::new(&mut write_buffer));

    tf.chainstate.export_bootstrap_stream(writer, with_stale_blocks).unwrap();

    assert!(write_buffer.starts_with(EXPECTED_MAGIC_BYTES.as_bytes()));

    write_buffer
}

fn import_from_slice_with_callback<C: Fn() -> std::io::Result<()> + Send>(
    tf: &mut TestFramework,
    bytes: &[u8],
    callback: C,
) -> Result<(), ChainstateError> {
    let reader = ReaderWithCallback {
        inner: bytes,
        callback,
    };
    let reader: std::io::BufReader<Box<dyn std::io::Read + Send>> =
        std::io::BufReader::new(Box::new(reader));

    tf.chainstate.import_bootstrap_stream(reader)
}

fn import_from_slice(tf: &mut TestFramework, bytes: &[u8]) -> Result<(), ChainstateError> {
    import_from_slice_with_callback(tf, bytes, || Ok(()))
}

struct ReaderWithCallback<R, C> {
    inner: R,
    callback: C,
}

impl<R: std::io::Read, C: Fn() -> std::io::Result<()>> std::io::Read for ReaderWithCallback<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (self.callback)()?;
        self.inner.read(buf)
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn successful_import_export(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let mut source_tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
        let genesis_id = source_tf.genesis().get_id();

        let chain1 = {
            source_tf.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();

            let tree_vec = source_tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = source_tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since there's only one chain, both should be equal
            assert_eq!(mainchain_vec, tree_vec);
            assert_eq!(mainchain_vec.len(), 5);

            check_height_order(&mainchain_vec, &source_tf);
            check_height_order(&tree_vec, &source_tf);

            mainchain_vec
        };

        let chain2 = {
            source_tf.create_chain(&genesis_id.into(), 15, &mut rng).unwrap();

            let tree_vec = source_tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = source_tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have more than one chain, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(mainchain_vec.len(), 15);
            assert_eq!(tree_vec.len(), 20);

            check_height_order(&mainchain_vec, &source_tf);
            check_height_order(&tree_vec, &source_tf);

            mainchain_vec
        };

        let chain3 = {
            source_tf.create_chain(&genesis_id.into(), 25, &mut rng).unwrap();

            let tree_vec = source_tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = source_tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have more than one chain, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert!(chain2.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(mainchain_vec.len(), 25);
            assert_eq!(tree_vec.len(), 45);

            check_height_order(&mainchain_vec, &source_tf);
            check_height_order(&tree_vec, &source_tf);

            mainchain_vec
        };

        let chain4 = {
            let len_to_cut_from_branch = 5;
            let new_branch_len = 35;
            source_tf
                .create_chain(
                    &chain2[chain2.len() - 1 - len_to_cut_from_branch].to_hash().into(),
                    new_branch_len,
                    &mut rng,
                )
                .unwrap();

            let tree_vec = source_tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = source_tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have more than one chain, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert!(chain2.iter().all(|item| tree_vec.contains(item)));
            assert!(chain3.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(
                mainchain_vec.len(),
                chain2.len() - len_to_cut_from_branch + new_branch_len
            );
            assert_eq!(tree_vec.len(), 45 + new_branch_len);

            check_height_order(&mainchain_vec, &source_tf);
            check_height_order(&tree_vec, &source_tf);

            mainchain_vec
        };

        // from now on, the original TestFramework cannot be modified
        let source_tf = source_tf;

        // double-check that we have all blocks of all chains
        {
            let tree_vec = source_tf.chainstate.get_block_id_tree_as_list().unwrap();

            let all_blocks = chain1
                .into_iter()
                .chain(chain2)
                .chain(chain3)
                .chain(chain4)
                .collect::<BTreeSet<Id<Block>>>();

            assert_eq!(
                all_blocks,
                tree_vec.iter().cloned().collect::<BTreeSet<Id<Block>>>()
            );

            tree_vec
        };

        let bootstrap_with_stale_blocks = export_to_vec(&source_tf, true);
        let bootstrap_no_stale_blocks = export_to_vec(&source_tf, false);

        // Test importing all blocks, including stale ones
        {
            let mut dest_tf =
                TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();

            // Import the blocks
            {
                import_from_slice(&mut dest_tf, &bootstrap_with_stale_blocks).unwrap();

                assert_eq!(
                    dest_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                    source_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                );
            }

            // Do it again; it shouldn't fail and just skip known blocks instead.
            {
                import_from_slice(&mut dest_tf, &bootstrap_with_stale_blocks).unwrap();

                assert_eq!(
                    dest_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                    source_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                );
            }
        }

        // Test importing all non-stale blocks
        {
            let mut dest_tf =
                TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();

            // Import the blocks
            {
                import_from_slice(&mut dest_tf, &bootstrap_no_stale_blocks).unwrap();

                // The dest_tf chain will only contain the mainchain
                assert_eq!(
                    dest_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                    source_tf.chainstate.get_mainchain_blocks_list().unwrap(),
                );

                assert_eq!(
                    dest_tf.chainstate.get_mainchain_blocks_list().unwrap(),
                    source_tf.chainstate.get_mainchain_blocks_list().unwrap(),
                );
            }

            // Now import the entire tree into the same test framework; it should skip already
            // existing blocks and import the rest.
            {
                import_from_slice(&mut dest_tf, &bootstrap_with_stale_blocks).unwrap();

                // The dest_tf chain will only contain the mainchain
                assert_eq!(
                    dest_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                    source_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                );
            }
        }
    });
}

// Construct v0 data manually and import it
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn exact_v0_format(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let mut source_tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
        let source_tf_genesis_id = source_tf.genesis().get_id();
        let blocks_count = rng.gen_range(5..10);
        source_tf
            .create_chain(&source_tf_genesis_id.into(), blocks_count, &mut rng)
            .unwrap();
        let source_tf_block_ids = source_tf.chainstate.get_block_id_tree_as_list().unwrap();

        let mut data = make_header_data(&chain_config, 0, blocks_count as u64);

        for block_id in &source_tf_block_ids {
            let encoded_block = source_tf.chainstate.get_block(block_id).unwrap().unwrap().encode();
            append_block_data_for_v0(&mut data, &encoded_block);
        }

        let mut dest_tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();

        import_from_slice(&mut dest_tf, &data).unwrap();

        assert_eq!(
            dest_tf.chainstate.get_block_id_tree_as_list().unwrap(),
            source_tf_block_ids,
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wrong_chain(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type1 = ChainType::iter().choose(&mut rng).unwrap();
        let chain_type2 =
            ChainType::iter().filter(|ct| ct != &chain_type1).choose(&mut rng).unwrap();

        let chain_config1 = make_chain_config(chain_type1);
        let chain_config2 = make_chain_config(chain_type2);

        let mut tf1 = TestFramework::builder(&mut rng).with_chain_config(chain_config1).build();
        let genesis1_id = tf1.genesis().get_id();

        tf1.create_chain(&genesis1_id.into(), 5, &mut rng).unwrap();
        let tf1_orig_block_ids = tf1.chainstate.get_block_id_tree_as_list().unwrap();
        let tf1_export = export_to_vec(&tf1, false);

        let mut tf2 = TestFramework::builder(&mut rng).with_chain_config(chain_config2).build();
        let genesis2_id = tf2.genesis().get_id();

        tf2.create_chain(&genesis2_id.into(), 5, &mut rng).unwrap();
        let tf2_orig_block_ids = tf2.chainstate.get_block_id_tree_as_list().unwrap();
        let tf2_export = export_to_vec(&tf2, false);

        // Import tf2's blocks into tf1
        let err = import_from_slice(&mut tf1, &tf2_export).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::BootstrapError(BootstrapError::WrongChain)
        );
        assert_eq!(
            tf1.chainstate.get_block_id_tree_as_list().unwrap(),
            tf1_orig_block_ids
        );

        // Import tf1's blocks into tf2
        let err = import_from_slice(&mut tf2, &tf1_export).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::BootstrapError(BootstrapError::WrongChain)
        );
        assert_eq!(
            tf2.chainstate.get_block_id_tree_as_list().unwrap(),
            tf2_orig_block_ids
        );
    });
}

// If the imported data starts with some chain's magic bytes, it should be recognized as
// the legacy file format.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn legacy_file_format(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
        let genesis_id = tf.genesis().get_id();
        tf.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();
        let orig_block_ids = tf.chainstate.get_block_id_tree_as_list().unwrap();

        for chain_type in ChainType::iter() {
            let data = [
                chain_type.magic_bytes().bytes().as_slice(),
                gen_random_bytes(&mut rng, 100, 1000).as_slice(),
            ]
            .concat();

            let err = import_from_slice(&mut tf, &data).unwrap_err();
            assert_eq!(
                err,
                ChainstateError::BootstrapError(BootstrapError::LegacyFileFormat)
            );

            assert_eq!(
                tf.chainstate.get_block_id_tree_as_list().unwrap(),
                orig_block_ids
            );
        }
    });
}

// Import data that only contains an incomplete header.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn file_too_small(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let mut tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
        let genesis_id = tf.genesis().get_id();
        tf.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();
        let orig_block_ids = tf.chainstate.get_block_id_tree_as_list().unwrap();

        let header_data = make_header_data(&chain_config, 0, rng.gen());

        let incomplete_header_data =
            &header_data[0..rng.gen_range(EXPECTED_MAGIC_BYTES.len()..header_data.len() - 1)];

        let err = import_from_slice(&mut tf, incomplete_header_data).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::BootstrapError(BootstrapError::FileTooSmall)
        );

        assert_eq!(
            tf.chainstate.get_block_id_tree_as_list().unwrap(),
            orig_block_ids
        );
    });
}

// The header's version field contains a non-supported version number (i.e. something other than 0).
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unsupported_version(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let mut tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
        let genesis_id = tf.genesis().get_id();
        tf.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();
        let orig_block_ids = tf.chainstate.get_block_id_tree_as_list().unwrap();

        let valid_blocks_count = rng.gen_range(1..5);
        let valid_blocks = gen_blocks(chain_config.clone(), valid_blocks_count, &mut rng);

        // Make a header with an unsupported version, followed by valid v0 data.
        let format_version = rng.gen_range(1..10);
        let mut data = make_header_data(&chain_config, format_version, valid_blocks_count as u64);
        for valid_block in &valid_blocks {
            let encoded_block = valid_block.encode();
            append_block_data_for_v0(&mut data, &encoded_block);
        }

        // Importing should fail right away and no blocks should be imported.
        let err = import_from_slice(&mut tf, &data).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::BootstrapError(BootstrapError::UnsupportedFutureFormatVersion)
        );

        assert_eq!(
            tf.chainstate.get_block_id_tree_as_list().unwrap(),
            orig_block_ids
        );

        // Sanity check - if we reset the version to zero, the import will succeed.
        data[12..16].fill(0);
        import_from_slice(&mut tf, &data).unwrap();
        let expected_block_ids = BTreeSet::from_iter(
            orig_block_ids
                .into_iter()
                .chain(valid_blocks.iter().map(|block| block.get_id())),
        );
        let actual_block_ids =
            BTreeSet::from_iter(tf.chainstate.get_block_id_tree_as_list().unwrap());
        assert_eq!(actual_block_ids, expected_block_ids);
    });
}

fn make_chain_config(chain_type: ChainType) -> ChainConfig {
    chain::config::Builder::new(chain_type)
        .consensus_upgrades(NetUpgrades::unit_tests())
        .data_in_no_signature_witness_allowed(true)
        .genesis_unittest(Destination::AnyoneCanSpend)
        // Force empty checkpoints because a custom genesis is used.
        .checkpoints(BTreeMap::new())
        .build()
}

// The data starts with wrong format magic bytes.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn wrong_format(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let mut tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
        let genesis_id = tf.genesis().get_id();
        tf.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();
        let orig_block_ids = tf.chainstate.get_block_id_tree_as_list().unwrap();

        let valid_blocks_count = rng.gen_range(1..5);
        let valid_blocks = gen_blocks(chain_config.clone(), valid_blocks_count, &mut rng);

        // Make a header with wrong format magic bytes, followed by valid v0 data.
        let mut data = make_header_data(&chain_config, 0, valid_blocks_count as u64);
        let byte_idx_to_mutate = rng.gen_range(0..EXPECTED_MAGIC_BYTES.len());
        data[byte_idx_to_mutate] = data[byte_idx_to_mutate].wrapping_add(rng.gen_range(1..255));
        for valid_block in &valid_blocks {
            let encoded_block = valid_block.encode();
            append_block_data_for_v0(&mut data, &encoded_block);
        }

        // Importing should fail right away and no blocks should be imported.
        let err = import_from_slice(&mut tf, &data).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::BootstrapError(BootstrapError::WrongFileFormat)
        );

        assert_eq!(
            tf.chainstate.get_block_id_tree_as_list().unwrap(),
            orig_block_ids
        );

        // Sanity check - if we overwrite format magic bytes with correct ones, the import will succeed.
        data[0..EXPECTED_MAGIC_BYTES.len()].copy_from_slice(EXPECTED_MAGIC_BYTES.as_bytes());
        import_from_slice(&mut tf, &data).unwrap();
        let expected_block_ids = BTreeSet::from_iter(
            orig_block_ids
                .into_iter()
                .chain(valid_blocks.iter().map(|block| block.get_id())),
        );
        let actual_block_ids =
            BTreeSet::from_iter(tf.chainstate.get_block_id_tree_as_list().unwrap());
        assert_eq!(actual_block_ids, expected_block_ids);
    });
}

// The file format is correct to some point, but then the data ends abruptly.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn bad_v0_file(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        #[derive(Debug, strum::EnumIter)]
        enum TestKind {
            BadBlockLenLen,
            BadBlockDataLen,
        }

        let valid_blocks_count = rng.gen_range(1..5);
        let valid_blocks = gen_blocks(chain_config.clone(), valid_blocks_count, &mut rng);

        for kind in TestKind::iter() {
            log::debug!("Kind is {kind:?}");

            let mut tf =
                TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
            let genesis_id = tf.genesis().get_id();
            tf.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();
            let orig_block_ids = tf.chainstate.get_block_id_tree_as_list().unwrap();

            // Make a header, followed by `valid_blocks_count-1` valid blocks.
            let mut data = make_header_data(&chain_config, 0, valid_blocks_count as u64);

            for valid_block in valid_blocks.iter().take(valid_blocks.len() - 1) {
                let encoded_block = valid_block.encode();
                append_block_data_for_v0(&mut data, &encoded_block);
            }

            let last_block_data = {
                let mut data = Vec::new();
                let encoded_block = valid_blocks.last().unwrap().encode();
                append_block_data_for_v0(&mut data, &encoded_block);
                data
            };

            let last_block_cutoff_pos = match kind {
                TestKind::BadBlockLenLen => {
                    // Either the file ends right after the previously written valid_blocks_count-1 blocks,
                    // or some portion of the block length field is present.
                    rng.gen_range(0..3)
                }
                TestKind::BadBlockDataLen => {
                    // The block length is correct, but the data after it is incomplete.
                    rng.gen_range(4..last_block_data.len() - 1)
                }
            };
            data.extend_from_slice(&last_block_data[0..last_block_cutoff_pos]);

            // Importing should fail when it reaches the bad block;
            // the correct ones should have been imported.
            let err = import_from_slice(&mut tf, &data).unwrap_err();
            assert_eq!(
                err,
                ChainstateError::BootstrapError(BootstrapError::BadFileFormat)
            );

            let expected_block_ids = BTreeSet::from_iter(orig_block_ids.into_iter().chain(
                valid_blocks.iter().take(valid_blocks.len() - 1).map(|block| block.get_id()),
            ));
            let actual_block_ids =
                BTreeSet::from_iter(tf.chainstate.get_block_id_tree_as_list().unwrap());
            assert_eq!(actual_block_ids, expected_block_ids);
        }
    });
}

// The recorded block size is too big.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn block_size_too_big(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let valid_blocks_count = rng.gen_range(0..5);
        let valid_blocks = gen_blocks(chain_config.clone(), valid_blocks_count, &mut rng);

        let mut tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();

        let mut data = make_header_data(&chain_config, 0, (valid_blocks_count + 1) as u64);

        for valid_block in valid_blocks {
            let encoded_block = valid_block.encode();
            append_block_data_for_v0(&mut data, &encoded_block);
        }

        let bad_block_size: u32 = 100 * 1024 * 1024;
        data.extend_from_slice(&bad_block_size.to_le_bytes());

        // Importing should fail with this specific error, meaning that we didn't attempt to
        // actually read the data.
        let err = import_from_slice(&mut tf, &data).unwrap_err();
        assert_eq!(
            err,
            ChainstateError::BootstrapError(BootstrapError::BlockSizeTooBig(
                bad_block_size as usize
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_reckless_mode(
    #[case] seed: Seed,
    #[values(None, Some(false), Some(true))] enable_db_reckless_mode_in_ibd: Option<bool>,
    #[values(false, true)] fail_on_read: bool,
) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_type = ChainType::iter().choose(&mut rng).unwrap();
        let chain_config = make_chain_config(chain_type);

        let mut source_tf =
            TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
        let genesis_id = source_tf.genesis().get_id();
        let blocks_count = rng.gen_range(5..10);
        source_tf.create_chain(&genesis_id.into(), blocks_count, &mut rng).unwrap();

        let block_ids = source_tf.chainstate.get_mainchain_blocks_list().unwrap();
        let exported_blocks = export_to_vec(&source_tf, true);

        let mut dest_tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.clone())
            .with_chainstate_config(ChainstateConfig {
                enable_db_reckless_mode_in_ibd,

                max_db_commit_attempts: Default::default(),
                max_orphan_blocks: Default::default(),
                max_tip_age: Default::default(),
                enable_heavy_checks: Default::default(),
                allow_checkpoints_mismatch: Default::default(),
            })
            .build();
        let use_reckless_mode = enable_db_reckless_mode_in_ibd.unwrap_or(false);
        let dest_tf_store = dest_tf.storage.clone();

        let result = import_from_slice_with_callback(&mut dest_tf, &exported_blocks, || {
            assert_eq!(dest_tf_store.in_reckless_mode().unwrap(), use_reckless_mode);

            if fail_on_read {
                Err(std::io::ErrorKind::Other.into())
            } else {
                Ok(())
            }
        });
        assert!(!dest_tf_store.in_reckless_mode().unwrap());

        if fail_on_read {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());

            assert_eq!(
                dest_tf.chainstate.get_block_id_tree_as_list().unwrap(),
                block_ids
            );
        }
    });
}

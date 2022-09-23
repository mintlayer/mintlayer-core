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

use serialization::Encode;
use std::collections::BTreeSet;
use std::io::BufWriter;

use chainstate::chainstate_interface::ChainstateInterface;
use chainstate::ChainstateConfig;
use chainstate_test_framework::TestFramework;
use common::chain::Block;
use common::primitives::Id;
use common::primitives::Idable;
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

/// Ensure that the blocks vector put blocks in order with height in the blockchain
fn check_height_order<C: ChainstateInterface>(blocks: &Vec<Id<Block>>, chainstate: &C) {
    let mut last_height = 0;
    for block_id in blocks {
        let height = chainstate
            .get_block_height_in_main_chain(&block_id.get().into())
            .expect("Database error")
            .expect("We loaded this from chainstate");
        let current_height: u64 = height.into();
        assert!(current_height >= last_height);
        last_height = current_height;
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn bootstrap_tests(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf1 = TestFramework::default();
        let genesis_id = tf1.genesis().get_id();

        let chain1 = {
            tf1.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();

            let _last_block_id = tf1.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf1.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf1.chainstate.get_mainchain_blocks_list().unwrap();

            // since there's only one chain, both should be equal
            assert_eq!(mainchain_vec, tree_vec);
            assert_eq!(mainchain_vec.len(), 5);

            check_height_order(&mainchain_vec, &tf1.chainstate);
            check_height_order(&tree_vec, &tf1.chainstate);

            mainchain_vec
        };

        let chain2 = {
            tf1.create_chain(&genesis_id.into(), 15, &mut rng).unwrap();

            let _last_block_id = tf1.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf1.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf1.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have orphans, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(mainchain_vec.len(), 15);
            assert_eq!(tree_vec.len(), 20);

            check_height_order(&mainchain_vec, &tf1.chainstate);
            check_height_order(&tree_vec, &tf1.chainstate);

            mainchain_vec
        };

        let chain3 = {
            tf1.create_chain(&genesis_id.into(), 25, &mut rng).unwrap();

            let _last_block_id = tf1.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf1.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf1.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have orphans, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert!(chain2.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(mainchain_vec.len(), 25);
            assert_eq!(tree_vec.len(), 45);

            check_height_order(&mainchain_vec, &tf1.chainstate);
            check_height_order(&tree_vec, &tf1.chainstate);

            mainchain_vec
        };

        let chain4 = {
            let len_to_cut_from_branch = 5;
            let new_branch_len = 35;
            tf1.create_chain(
                &chain2[chain2.len() - 1 - len_to_cut_from_branch].get().into(),
                new_branch_len,
                &mut rng,
            )
            .unwrap();

            let _last_block_id = tf1.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf1.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf1.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have orphans, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert!(chain2.iter().all(|item| tree_vec.contains(item)));
            assert!(chain3.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(
                mainchain_vec.len(),
                chain2.len() - len_to_cut_from_branch + new_branch_len
            );
            assert_eq!(tree_vec.len(), 45 + new_branch_len);

            check_height_order(&mainchain_vec, &tf1.chainstate);
            check_height_order(&tree_vec, &tf1.chainstate);

            mainchain_vec
        };

        // double-check that we have all blocks of all chains
        let all_blocks = {
            let tree_vec = tf1.chainstate.get_block_id_tree_as_list().unwrap();

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

        // get max block size to test buffers on threshold
        let largest_block_size = {
            all_blocks
                .iter()
                .map(|id| {
                    tf1.chainstate
                        .get_block(*id)
                        .expect("Block read failed")
                        .expect("Block not found even though we just read it")
                        .encoded_size()
                })
                .max()
                .expect("The list can't be empty so this must have something in it")
        };

        // bootstrap export
        let make_bootstrap_as_vec = |with_orphans: bool| {
            let mut write_buffer = Vec::new();

            let buf: BufWriter<Box<dyn std::io::Write + Send>> =
                std::io::BufWriter::new(Box::new(&mut write_buffer));
            let writer = std::sync::Mutex::new(buf);

            tf1.chainstate.export_bootstrap_stream(writer, with_orphans).unwrap();

            write_buffer
        };

        let bootstrap_with_orphans = make_bootstrap_as_vec(true);
        let bootstrap_no_orphans = make_bootstrap_as_vec(false);

        // test importing all blocks with orphans
        {
            let mut tf2 = TestFramework::builder()
                .with_chainstate_config(
                    ChainstateConfig::new()
                        .with_max_orphan_blocks(0)
                        .with_bootstrap_buffer_sizes((largest_block_size, 2 * largest_block_size)),
                )
                .build();

            let buf: std::io::BufReader<Box<dyn std::io::Read + Send>> =
                std::io::BufReader::new(Box::new(bootstrap_with_orphans.as_slice()));
            let reader = std::sync::Mutex::new(buf);

            tf2.chainstate.import_bootstrap_stream(reader).unwrap();

            assert_eq!(
                tf2.chainstate.get_block_id_tree_as_list().unwrap(),
                tf1.chainstate.get_block_id_tree_as_list().unwrap(),
            );
        }

        // test importing all blocks with no orphans
        {
            let mut tf3 = TestFramework::builder()
                .with_chainstate_config(
                    ChainstateConfig::new()
                        .with_max_orphan_blocks(0)
                        .with_bootstrap_buffer_sizes((largest_block_size, 2 * largest_block_size)),
                )
                .build();

            let buf: std::io::BufReader<Box<dyn std::io::Read + Send>> =
                std::io::BufReader::new(Box::new(bootstrap_no_orphans.as_slice()));
            let reader = std::sync::Mutex::new(buf);

            tf3.chainstate.import_bootstrap_stream(reader).unwrap();

            assert_eq!(
                tf3.chainstate.get_mainchain_blocks_list().unwrap(),
                tf1.chainstate.get_mainchain_blocks_list().unwrap(),
            );
        }

        // test importing all blocks with orphans with default buffer size
        {
            let mut tf4 = TestFramework::builder()
                .with_chainstate_config(ChainstateConfig::new().with_max_orphan_blocks(0))
                .build();

            let buf: std::io::BufReader<Box<dyn std::io::Read + Send>> =
                std::io::BufReader::new(Box::new(bootstrap_with_orphans.as_slice()));
            let reader = std::sync::Mutex::new(buf);

            tf4.chainstate.import_bootstrap_stream(reader).unwrap();

            assert_eq!(
                tf4.chainstate.get_block_id_tree_as_list().unwrap(),
                tf1.chainstate.get_block_id_tree_as_list().unwrap(),
            );
        }

        // test importing all blocks with orphans with small huge buffers
        {
            let mut tf5 = TestFramework::builder()
                .with_chainstate_config(
                    ChainstateConfig::new()
                        .with_max_orphan_blocks(0)
                        .with_bootstrap_buffer_sizes((usize::MAX / 2, usize::MAX / 2)),
                )
                .build();

            let buf: std::io::BufReader<Box<dyn std::io::Read + Send>> =
                std::io::BufReader::new(Box::new(bootstrap_with_orphans.as_slice()));
            let reader = std::sync::Mutex::new(buf);

            tf5.chainstate.import_bootstrap_stream(reader).unwrap();

            assert_eq!(
                tf5.chainstate.get_block_id_tree_as_list().unwrap(),
                tf1.chainstate.get_block_id_tree_as_list().unwrap(),
            );
        }
    });
}

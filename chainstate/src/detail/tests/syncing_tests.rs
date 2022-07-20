// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen

use std::iter;

use crate::detail::tests::{test_framework::BlockTestFramework, *};
use chainstate_storage::BlockchainStorageRead;
use crypto::random::{self, Rng};

#[test]
fn locator_distances() {
    let distances: Vec<i64> = Chainstate::locator_tip_distances().take(7).map(From::from).collect();
    assert_eq!(distances, vec![0, 1, 2, 4, 8, 16, 32]);
}

// Generate some blocks and check that a locator is of expected length.
#[test]
fn get_locator() {
    common::concurrency::model(|| {
        let mut btf = BlockTestFramework::new();

        // There is only one (genesis) block.
        let locator = btf.chainstate().get_locator().unwrap();
        assert_eq!(locator.len(), 1);
        assert_eq!(&btf.genesis().get_id(), &locator[0]);

        // Expand the chain several times.
        let mut rng = random::make_pseudo_rng();
        let mut blocks = 1;
        let mut last_block = btf.genesis().clone();
        for _ in 0..8 {
            let new_blocks = rng.gen_range(1..2000);
            last_block = btf.create_chain(&last_block.get_id(), new_blocks).unwrap();
            blocks += new_blocks;

            // Check the locator length.
            let locator = btf.chainstate().get_locator().unwrap();
            assert_eq!(locator.len(), (blocks as f64).log2().ceil() as usize + 1);

            // Check the locator headers.
            let height = btf
                .chainstate()
                .get_block_height_in_main_chain(&last_block.get_id())
                .unwrap()
                .unwrap();
            assert_eq!(&locator[0], &last_block.get_id());
            for (i, header) in locator.iter().skip(1).enumerate() {
                let idx = height - BlockDistance::new(2i64.pow(i as u32));
                let expected =
                    btf.chainstate().get_block_id_from_height(&idx.unwrap()).unwrap().unwrap();
                assert_eq!(&expected, header);
            }
        }
    });
}

// Check that new blocks (produced after a locator is created) are returned.
#[test]
fn get_headers() {
    common::concurrency::model(|| {
        let mut rng = random::make_pseudo_rng();
        let header_limit = i64::from(HEADER_LIMIT).try_into().unwrap();

        let mut btf = BlockTestFramework::new();
        let mut last_block = btf.genesis().clone();
        last_block = btf.create_chain(&last_block.get_id(), rng.gen_range(1000..2000)).unwrap();

        // The locator is from this exact chain, so `get_headers` should return an empty sequence.
        let locator = btf.chainstate().get_locator().unwrap();
        assert_eq!(
            btf.chainstate().get_headers(locator.clone()).unwrap(),
            vec![]
        );

        // Produce more blocks. Now `get_headers` should return these blocks.
        let expected: Vec<_> = iter::from_fn(|| {
            last_block = produce_test_block(&last_block, false);
            btf.chainstate()
                .process_block(last_block.clone(), BlockSource::Peer)
                .ok()
                .flatten()
                .unwrap();
            Some(last_block.header().clone())
        })
        .take(rng.gen_range(1000..header_limit))
        .collect();

        let headers = btf.chainstate().get_headers(locator.clone()).unwrap();
        assert_eq!(headers, expected);
        // Because both the locator and chainstate are tracking the same chain, the first header of
        // the locator is always the parent of the first new block.
        assert_eq!(expected[0].prev_block_id(), &Some(locator[0].clone()));

        // Produce more blocks than `HEADER_LIMIT`, so get_headers is truncated.
        btf.create_chain(&last_block.get_id(), header_limit - expected.len()).unwrap();
        let headers = btf.chainstate().get_headers(locator).unwrap();
        assert_eq!(headers.len(), header_limit);
    });
}

// Create two chains that only share the genesis block and verify that the header is attached to
// the genesis.
#[test]
fn get_headers_genesis() {
    common::concurrency::model(|| {
        let mut rng = random::make_pseudo_rng();

        let mut btf = BlockTestFramework::new();
        let genesis = btf.genesis().clone();

        btf.create_chain(&genesis.get_id(), rng.gen_range(64..128)).unwrap();
        let locator_1 = btf.chainstate.get_locator().unwrap();

        let chain_length = rng.gen_range(1200..2000);
        btf.create_chain(&genesis.get_id(), chain_length).unwrap();
        let locator_2 = btf.chainstate.get_locator().unwrap();
        assert_ne!(locator_1, locator_2);
        assert!(locator_1.len() < locator_2.len());

        let headers = btf.chainstate.get_headers(locator_1).unwrap();
        assert_eq!(headers[0].prev_block_id(), &Some(genesis.get_id()));
        assert_eq!(headers.len(), chain_length);
    });
}

// Create two chains that branch at some point, both with some unique blocks. Verify that the first
// returned header is attached to a block that is known to both chains.
#[test]
fn get_headers_branching_chains() {
    common::concurrency::model(|| {
        let mut rng = random::make_pseudo_rng();
        let common_height = rng.gen_range(100..10_000);

        let mut btf = BlockTestFramework::new();
        let common_block = btf.create_chain(&btf.genesis().get_id(), common_height).unwrap();

        btf.create_chain(&common_block.get_id(), rng.gen_range(100..2500)).unwrap();
        let locator = btf.chainstate.get_locator().unwrap();
        btf.create_chain(&common_block.get_id(), rng.gen_range(2500..5000)).unwrap();

        let headers = btf.chainstate.get_headers(locator).unwrap();
        let id = headers[0].prev_block_id().as_ref().unwrap();
        assert!(btf.get_block_index(id).block_height() <= BlockHeight::new(common_height as u64));
    });
}

// Create two separate chains that share some blocks. Verify that the first returned header is
// attached to some block known for both chains.
#[test]
fn get_headers_different_chains() {
    common::concurrency::model(|| {
        let mut rng = random::make_pseudo_rng();

        let mut btf1 = BlockTestFramework::new();
        let mut btf2 = BlockTestFramework::new();

        let mut prev = btf1.genesis().clone();
        assert_eq!(&prev, btf2.genesis());
        for _ in 0..rng.gen_range(100..250) {
            prev = btf1.random_block(&prev, None);
            btf1.add_special_block(prev.clone()).unwrap();
            btf2.add_special_block(prev.clone()).unwrap();
            assert_eq!(
                btf1.block_indexes.last().unwrap().block_id(),
                btf2.block_indexes.last().unwrap().block_id()
            );
        }

        btf1.create_chain(&prev.get_id(), rng.gen_range(32..256)).unwrap();
        btf2.create_chain(&prev.get_id(), rng.gen_range(256..512)).unwrap();

        let locator = btf1.chainstate.get_locator().unwrap();
        let headers = btf2.chainstate.get_headers(locator).unwrap();
        let id = headers[0].prev_block_id().clone().unwrap();
        assert!(btf1.chainstate.chainstate_storage.get_block_index(&id).unwrap().is_some());

        let locator = btf2.chainstate.get_locator().unwrap();
        let headers = btf1.chainstate.get_headers(locator).unwrap();
        let id = headers[0].prev_block_id().clone().unwrap();
        assert!(btf2.chainstate.chainstate_storage.get_block_index(&id).unwrap().is_some());
    });
}

#[test]
fn filter_already_existing_blocks() {
    common::concurrency::model(|| {
        let mut rng = random::make_pseudo_rng();

        let mut btf1 = BlockTestFramework::new();
        let mut btf2 = BlockTestFramework::new();

        let mut prev1 = btf1.genesis().clone();
        for _ in 0..rng.gen_range(8..16) {
            prev1 = btf1.random_block(&prev1, None);
            btf1.add_special_block(prev1.clone()).unwrap();
            btf2.add_special_block(prev1.clone()).unwrap();
            assert_eq!(
                btf1.block_indexes.last().unwrap().block_id(),
                btf2.block_indexes.last().unwrap().block_id(),
            );
        }

        let limit = rng.gen_range(32..256);
        let mut prev2 = prev1.clone();
        let mut headers1 = vec![];
        let mut headers2 = vec![];

        // Add random blocks to both chains.
        for i in 0..(limit * 2) {
            if i <= limit {
                prev1 = btf1.random_block(&prev1, None);
                headers1.push(prev1.header().clone());
                btf1.add_special_block(prev1.clone()).unwrap();
            }

            prev2 = btf1.random_block(&prev2, None);
            headers2.push(prev2.header().clone());
            btf2.add_special_block(prev2.clone()).unwrap();
        }

        // Check that filter_already_existing_blocks retains only unique to other chain blocks.
        let locator = btf1.chainstate.get_locator().unwrap();
        let headers = btf2.chainstate.get_headers(locator).unwrap();
        assert!(headers.len() >= headers2.len());
        let headers = btf1.chainstate.filter_already_existing_blocks(headers).unwrap();
        assert_eq!(headers, headers2);

        let locator = btf2.chainstate.get_locator().unwrap();
        let headers = btf1.chainstate.get_headers(locator).unwrap();
        assert!(headers.len() >= headers1.len());
        let headers = btf2.chainstate.filter_already_existing_blocks(headers).unwrap();
        assert_eq!(headers, headers1);
    });
}

// Try to use headers that aren't attached to the chain.
#[test]
fn filter_already_existing_blocks_detached_headers() {
    common::concurrency::model(|| {
        let mut rng = random::make_pseudo_rng();

        let mut btf1 = BlockTestFramework::new();
        let mut btf2 = BlockTestFramework::new();

        let mut prev = btf1.genesis().clone();
        for _ in 0..rng.gen_range(8..16) {
            prev = btf1.random_block(&prev, None);
            btf1.add_special_block(prev.clone()).unwrap();
            btf2.add_special_block(prev.clone()).unwrap();
            assert_eq!(
                btf1.block_indexes.last().unwrap().block_id(),
                btf2.block_indexes.last().unwrap().block_id(),
            );
        }

        let headers = (0..rng.gen_range(3..10))
            .map(|_| {
                prev = btf2.random_block(&prev, None);
                btf2.add_special_block(prev.clone()).unwrap();
                prev.header().clone()
            })
            .collect::<Vec<_>>();

        let filtered_headers =
            btf1.chainstate.filter_already_existing_blocks(headers[1..].to_vec());
        assert_eq!(
            filtered_headers,
            Err(PropertyQueryError::BlockNotFound(
                headers[1].prev_block_id().clone().unwrap()
            ))
        );
    });
}

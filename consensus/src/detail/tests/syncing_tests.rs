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
use crate::detail::tests::*;

#[test]
fn test_get_locator() {
    common::concurrency::model(|| {
        let config = Arc::new(create_mainnet());
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(Arc::clone(&config), storage).unwrap();

        let mut prev_block = consensus.chain_config.genesis_block().clone();
        let limit = rand::thread_rng().gen::<u16>();

        for _ in 0..limit {
            let new_block = produce_test_block(&consensus.chain_config, &prev_block, false);
            consensus
                .process_block(new_block.clone(), BlockSource::Peer(1))
                .ok()
                .flatten()
                .unwrap();
            prev_block = new_block;
        }
        let locator = consensus.get_locator().unwrap();

        // only genesis
        if limit == 0 {
            assert_eq!(locator.len(), 1);
        } else {
            assert_eq!(locator.len(), (limit as f64).log2().floor() as usize + 2);
        }

        // verify that the locator selected correct headers
        let height =
            consensus.get_block_height_in_main_chain(&prev_block.get_id()).unwrap().unwrap();
        assert_eq!(&locator[0], prev_block.header());
        let iter = locator.iter().skip(1);

        for (header, i) in iter.zip(0..locator.len() - 1) {
            let idx = height - BlockDistance::new(2i64.pow(i as u32));
            let correct = consensus.get_header_from_height(&idx.unwrap()).unwrap().unwrap();
            assert_eq!(&correct, header);
        }
    });
}

#[test]
fn test_get_headers_same_chain() {
    common::concurrency::model(|| {
        let config = Arc::new(create_mainnet());
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config, storage).unwrap();

        let mut prev_block = consensus.chain_config.genesis_block().clone();
        let limit = rand::thread_rng().gen::<u16>();

        for _ in 0..limit {
            let new_block = produce_test_block(&consensus.chain_config, &prev_block, false);
            consensus
                .process_block(new_block.clone(), BlockSource::Peer(1))
                .ok()
                .flatten()
                .unwrap();
            prev_block = new_block;
        }

        // first check that if the two chains are in sync, no headers are returned
        let locator = consensus.get_locator().unwrap();
        assert_eq!(consensus.get_headers(locator.clone()).unwrap(), vec![]);

        // then add some blocks while keeping the old locator and verify that
        // that only headers of the new blocks are returned
        let limit = rand::thread_rng().gen::<u16>();
        let mut headers = vec![];

        for _ in 0..limit {
            let new_block = produce_test_block(&consensus.chain_config, &prev_block, false);
            headers.push(new_block.header().clone());
            consensus
                .process_block(new_block.clone(), BlockSource::Peer(1))
                .ok()
                .flatten()
                .unwrap();
            prev_block = new_block;
        }

        let new_received_headers = consensus.get_headers(locator.clone()).unwrap();
        let hdr_limit = if limit > 2000 { 2000 } else { headers.len() };

        // verify that the received headers match expected and that they attach to locator
        //
        // because both locator and `consesus` are tracking the same chain, the first header
        // of locator is always the parent of the first header in `new_received_headers`
        assert_eq!(new_received_headers, headers[..hdr_limit]);
        assert_eq!(headers[0].get_prev_block_id(), &Some(locator[0].block_id()));
    });
}

#[test]
fn test_get_headers_different_chains() {
    use crate::detail::tests::test_framework::BlockTestFrameWork;
    common::concurrency::model(|| {
        // first create test where the chains have branched off at genesis
        // verify that the first header attaches to genesis
        {
            let mut btf = BlockTestFrameWork::new();
            let limit = rand::thread_rng().gen_range(0..10_000);
            btf.create_chain(
                &btf.genesis().get_id(),
                (limit / 10) as usize,
                produce_test_block,
            );

            let locator = btf.consensus.get_locator().unwrap();
            btf.create_chain(&btf.genesis().get_id(), limit, produce_test_block);

            // verify that the locators are different now that the chain has more headers
            assert!(locator.len() < btf.consensus.get_locator().unwrap().len());

            let new_headers = btf.consensus.get_headers(locator).unwrap();
            assert_eq!(
                new_headers[0].get_prev_block_id(),
                &Some(btf.genesis().get_id()),
            );
        }

        // create two chains which branch at some random point and
        // add random amount of blocks to both chains.
        //
        // Verify that the first returned header attaches to the other chain
        {
            let mut btf = BlockTestFrameWork::new();
            let common_height = rand::thread_rng().gen_range(100..10_000);
            btf.create_chain(&btf.genesis().get_id(), common_height, produce_test_block);

            let limit = rand::thread_rng().gen_range(100..2500);
            btf.create_chain(
                &btf.blocks[common_height - 1].get_id(),
                limit,
                produce_test_block,
            );
            let locator = btf.consensus.get_locator().unwrap();
            btf.create_chain(
                &btf.blocks[common_height - 1].get_id(),
                limit * 4,
                produce_test_block,
            );

            let new_headers = btf.consensus.get_headers(locator).unwrap();

            // verify that the new header attaches to a block that is in
            // the set of blocks that is know by both chains (it's height <= common_height)
            let id = new_headers[0].get_prev_block_id().clone().unwrap();
            assert!(
                btf.get_block_index(&id).get_block_height()
                    <= BlockHeight::new(common_height as u64)
            );
        }

        // create two chains which branch and where the the chain which
        // is used for the locator is shorter
        //
        // Verify that the first returned header attaches before genesis
        {
            let mut btf1 = BlockTestFrameWork::new();
            let mut btf2 = BlockTestFrameWork::new();
            let mut prev = btf1.genesis().clone();
            for _ in 0..rand::thread_rng().gen_range(100..250) {
                prev = btf1.random_block(&prev, None);
                btf1.add_special_block(prev.clone()).unwrap();
                btf2.add_special_block(prev.clone()).unwrap();
                assert_eq!(
                    btf1.blocks[btf1.blocks.len() - 1],
                    btf2.blocks[btf2.blocks.len() - 1],
                );
            }

            let limit = rand::thread_rng().gen_range(32..256);
            btf1.create_chain(
                &btf1.blocks[btf1.blocks.len() - 1].get_id(),
                limit,
                produce_test_block,
            );
            btf2.create_chain(
                &btf2.blocks[btf2.blocks.len() - 1].get_id(),
                limit * 2,
                produce_test_block,
            );

            let locator = btf1.consensus.get_locator().unwrap();
            let headers = btf2.consensus.get_headers(locator).unwrap();
            let id = headers[0].get_prev_block_id().clone().unwrap();
            assert!(btf1.consensus.blockchain_storage.get_block_index(&id).unwrap().is_some());

            let locator = btf2.consensus.get_locator().unwrap();
            let headers = btf1.consensus.get_headers(locator).unwrap();
            let id = headers[0].get_prev_block_id().clone().unwrap();
            assert!(btf2.consensus.blockchain_storage.get_block_index(&id).unwrap().is_some());
        }
    });
}

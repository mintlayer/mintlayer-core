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
// Author(s): S. Afach, A. Sinitsyn

use std::sync::Mutex;

use crate::detail::tests::test_framework::BlockTestFrameWork;
use crate::detail::tests::*;
use blockchain_storage::Store;
use common::chain::config::create_mainnet;

#[test]
fn test_reorg_simple() {
    common::concurrency::model(|| {
        let config = Arc::new(create_mainnet());
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new_no_genesis(config, storage).unwrap();

        // process the genesis block
        let result = consensus.process_block(
            consensus.chain_config.genesis_block().clone(),
            BlockSource::Local,
        );
        assert!(result.is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(consensus.chain_config.genesis_block().get_id())
        );

        // Process the second block
        let block = produce_test_block(consensus.chain_config.genesis_block(), false);
        let new_id = Some(block.get_id());
        assert!(consensus.process_block(block, BlockSource::Local).is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            new_id
        );

        // Process the parallel block and choose the better one
        let block = produce_test_block(consensus.chain_config.genesis_block(), false);
        // let new_id = Some(block.get_id());
        assert!(consensus.process_block(block.clone(), BlockSource::Local).is_ok());
        assert_ne!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(consensus.chain_config.genesis_block().get_id())
        );
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            new_id
        );

        // Produce another block that cause reorg
        let new_block = produce_test_block(&block, false);
        let new_id = Some(new_block.get_id());
        assert!(consensus.process_block(new_block, BlockSource::Local).is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            new_id
        );
    });
}

#[test]
fn test_very_long_reorgs() {
    common::concurrency::model(|| {
        let mut btf = BlockTestFrameWork::new();
        let events: EventList = Arc::new(Mutex::new(Vec::new()));
        subscribe_to_events(&mut btf, &events);

        check_simple_fork(&mut btf, &events);
        check_make_alternative_chain_longer(&mut btf, &events);
        check_reorg_to_first_chain(&mut btf, &events);
        check_spend_tx_in_failed_block(&mut btf, &events);
        check_spend_tx_in_other_fork(&mut btf);
        check_fork_that_double_spends(&mut btf);

        //  Try to create a block that has too much fee
        //      genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        //                                                     \-> b9 (4)
        //                       \-> b3 (1) -> b4 (2)
        // Reject a block where the miner creates too much reward
        //TODO: We have not decided yet how's done it correctly. We'll return here later.

        //  Create a fork that ends in a block with too much fee (the one that causes the reorg)
        //      genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                           \-> b10 (3) -> b11 (4)
        //                       \-> b3 (1) -> b4 (2)
        // Reject a chain where the miner creates too much coinbase reward, even if the chain is longer
        //
        //TODO: We have not decided yet how's done it correctly. We'll return here later.
    });
}

fn check_spend_tx_in_failed_block(btf: &mut BlockTestFrameWork, events: &EventList) {
    // Check spending of a transaction in a block which failed to connect
    //
    //+-- 0x07e3…6fe4 (H:8,M,B:10)
    //      +-- 0xe40f…4d5b (H:9,M,B:11)  <-------------------------------+
    //      +-- 0xe35a…7737 (H:9,M,B:12) spend tx from the previous block +
    //
    const NEW_CHAIN_START_ON: usize = 6;
    const NEW_CHAIN_END_ON: usize = 11;

    assert!(btf
        .create_chain(
            &btf.block_indexes[NEW_CHAIN_START_ON].get_block_id().clone(),
            5,
        )
        .is_ok());
    check_last_event(btf, events);

    let block = btf
        .consensus
        .blockchain_storage
        .get_block(btf.block_indexes[NEW_CHAIN_END_ON - 1].get_block_id().clone())
        .unwrap()
        .unwrap();

    let double_spend_block = btf.random_block(
        &block,
        Some(&[TestBlockParams::SpendFrom(
            btf.block_indexes[NEW_CHAIN_END_ON].get_block_id().clone(),
        )]),
    );
    assert!(btf.add_special_block(double_spend_block).is_ok());
    // Cause reorg on a failed block
    assert!(btf.create_chain(&btf.block_indexes[12].get_block_id().clone(), 1).is_err());
}

fn check_spend_tx_in_other_fork(btf: &mut BlockTestFrameWork) {
    // # Attempt to spend a transaction created on a different fork
    //
    // +-- 0x4273…c93c (H:7,M,B:10)
    //      <= Try to create a new block after this that spend B10 and B3 in fork
    // +-- 0xdf27…0fa5 (H:2,B:3)
    //          +-- 0x67fd…6419 (H:3,B:4)
    // > H - Height, M - main chain, B - block
    //
    // Reject a block with a spend from a re-org'ed out tx
    //
    const NEW_CHAIN_START_ON: usize = 5;
    const NEW_CHAIN_END_ON: usize = 9;
    assert!(btf
        .create_chain(
            &btf.block_indexes[NEW_CHAIN_START_ON].get_block_id().clone(),
            1
        )
        .is_ok());
    let block = btf
        .consensus
        .blockchain_storage
        .get_block(btf.block_indexes[NEW_CHAIN_END_ON].get_block_id().clone())
        .unwrap()
        .unwrap();
    let double_spend_block = btf.random_block(
        &block,
        Some(&[TestBlockParams::SpendFrom(btf.block_indexes[3].get_block_id().clone())]),
    );
    let block_id = double_spend_block.get_id();
    assert!(btf.add_special_block(double_spend_block).is_ok());
    // Cause reorg on a failed block
    assert!(btf.create_chain(&block_id, 10).is_err());
}

fn check_fork_that_double_spends(btf: &mut BlockTestFrameWork) {
    // # Try to create a fork that double-spends
    // +-- 0x6e45…e8e8 (H:0,P:0)
    //         +-- 0xe090…995e (H:1,M,P:1)
    //                 +-- 0x3562…2fb3 (H:2,M,P:2)
    //                         +-- 0xc92d…04c7 (H:3,M,P:5)
    //                                 +-- 0x9dbb…e52f (H:4,M,P:6)
    //                 +-- 0xdf27…0fa5 (H:2,P:3)
    //                         +-- 0x67fd…6419 (H:3,P:4)
    // > H - Height, M - main chain, B - block
    //
    // Reject a chain with a double spend, even if it is longer
    //
    let block = btf
        .consensus
        .blockchain_storage
        .get_block(btf.block_indexes.last().unwrap().get_block_id().clone())
        .unwrap()
        .unwrap();
    let double_spend_block = btf.random_block(
        &block,
        Some(&[TestBlockParams::SpendFrom(btf.block_indexes[6].get_block_id().clone())]),
    );
    assert!(btf.add_special_block(double_spend_block).is_err());
}

fn check_reorg_to_first_chain(btf: &mut BlockTestFrameWork, events: &EventList) {
    //  ... and back to the first chain.
    //
    // +-- 0x6e45…e8e8 (H:0,B:0)
    //         +-- 0xe090…995e (H:1,M,B:1)
    //                 +-- 0x3562…2fb3 (H:2,M,B:2)
    //                         +-- 0xc92d…04c7 (H:3,M,B:5)
    //                                 +-- 0x9dbb…e52f (H:4,M,B:6)
    //                 +-- 0xdf27…0fa5 (H:2,B:3)
    //                         +-- 0x67fd…6419 (H:3,B:4))
    // > H - Height, M - main chain, B - block
    //
    let block_id = btf.block_indexes[2].get_block_id().clone();
    assert!(btf.create_chain(&block_id, 2).is_ok());
    check_last_event(btf, events);

    // b3
    btf.test_block(
        btf.block_indexes[3].get_block_id(),
        Some(btf.block_indexes[1].get_block_id()),
        None,
        2,
        TestSpentStatus::NotInMainchain,
    );
    assert!(!btf.is_block_in_main_chain(btf.block_indexes[3].get_block_id()));
    // b4
    btf.test_block(
        btf.block_indexes[4].get_block_id(),
        Some(btf.block_indexes[3].get_block_id()),
        None,
        3,
        TestSpentStatus::NotInMainchain,
    );
    assert!(!btf.is_block_in_main_chain(btf.block_indexes[4].get_block_id()));
    // b5
    btf.test_block(
        btf.block_indexes[5].get_block_id(),
        Some(btf.block_indexes[2].get_block_id()),
        Some(btf.block_indexes[6].get_block_id()),
        3,
        TestSpentStatus::Spent,
    );
    assert!(btf.is_block_in_main_chain(btf.block_indexes[5].get_block_id()));
    // b6
    btf.test_block(
        btf.block_indexes[6].get_block_id(),
        Some(btf.block_indexes[5].get_block_id()),
        None,
        4,
        TestSpentStatus::Unspent,
    );
    assert!(btf.is_block_in_main_chain(btf.block_indexes[6].get_block_id()));
}

fn check_make_alternative_chain_longer(btf: &mut BlockTestFrameWork, events: &EventList) {
    //  Now we add another block to make the alternative chain longer.
    //
    // +-- 0x6e45…e8e8 (H:0,B:0)
    //         +-- 0xe090…995e (H:1,M,B:1)
    //                 +-- 0x3562…2fb3 (H:2,B:2)
    //                 +-- 0xdf27…0fa5 (H:2,M,B:3)
    //                         +-- 0x67fd…6419 (H:3,M,B:4)
    // > H - Height, M - main chain, B - block
    //
    // Reorg to a longer chain
    //
    let block = btf
        .consensus
        .blockchain_storage
        .get_block(btf.block_indexes.last().unwrap().get_block_id().clone())
        .unwrap()
        .unwrap();
    let block = btf.random_block(&block, None);
    assert!(btf.add_special_block(block).is_ok());
    check_last_event(btf, events);
    // b3
    btf.test_block(
        btf.block_indexes[3].get_block_id(),
        Some(btf.block_indexes[1].get_block_id()),
        Some(btf.block_indexes[4].get_block_id()),
        2,
        TestSpentStatus::Spent,
    );
    assert!(btf.is_block_in_main_chain(btf.block_indexes[3].get_block_id()));
    // b4
    btf.test_block(
        btf.block_indexes[4].get_block_id(),
        Some(btf.block_indexes[3].get_block_id()),
        None,
        3,
        TestSpentStatus::Unspent,
    );
    assert!(btf.is_block_in_main_chain(btf.block_indexes[4].get_block_id()));
}

fn check_simple_fork(btf: &mut BlockTestFrameWork, events: &EventList) {
    //  Fork like this:
    //
    //  +-- 0x6e45…e8e8 (H:0,B:0) = genesis
    //         +-- 0xe090…995e (H:1,M,B:1)
    //                 +-- 0x3562…2fb3 (H:2,M,B:2)
    //                 +-- 0xdf27…0fa5 (H:2,B:3)
    // > H - Height, M - main chain, B - block
    //
    // Nothing should happen at this point. We saw B2 first so it takes priority.
    // Don't reorg to a chain of the same length
    assert!(btf.create_chain(&btf.genesis().get_id(), 2).is_ok());
    check_last_event(btf, events);
    assert!(btf.create_chain(&btf.block_indexes[1].get_block_id().clone(), 1).is_ok());
    check_last_event(btf, events);

    // genesis
    btf.test_block(
        btf.block_indexes[0].get_block_id(),
        None,
        Some(btf.block_indexes[1].get_block_id()),
        0,
        TestSpentStatus::Spent,
    );
    // b1
    btf.test_block(
        btf.block_indexes[1].get_block_id(),
        Some(&btf.genesis().get_id()),
        Some(btf.block_indexes[2].get_block_id()),
        1,
        TestSpentStatus::Spent,
    );
    assert!(btf.is_block_in_main_chain(btf.block_indexes[1].get_block_id()));
    // b2
    btf.test_block(
        btf.block_indexes[2].get_block_id(),
        Some(btf.block_indexes[1].get_block_id()),
        None,
        2,
        TestSpentStatus::Unspent,
    );
    assert!(btf.is_block_in_main_chain(btf.block_indexes[2].get_block_id()));
    // b3
    btf.test_block(
        btf.block_indexes[3].get_block_id(),
        Some(btf.block_indexes[1].get_block_id()),
        None,
        2,
        TestSpentStatus::NotInMainchain,
    );
    assert!(!btf.is_block_in_main_chain(btf.block_indexes[3].get_block_id()));
}

fn check_last_event(btf: &mut BlockTestFrameWork, events: &EventList) {
    // We don't send any events for blocks in the middle of the chain during reorgs.
    wait_for_threadpool_to_finish(&mut btf.consensus);
    let events = events.lock().unwrap();
    assert!(!events.is_empty());
    match events.last() {
        Some((block_id, block_height)) => {
            let block_index = btf.block_indexes.last().unwrap();
            if btf.is_block_in_main_chain(block_index.get_block_id()) {
                // If block not in main chain then it means we didn't receive a new tip event. Nothing to check!
                assert!(block_id == block_index.get_block_id());
                assert!(block_height == &block_index.get_block_height());
            }
        }
        None => {
            dbg!(btf.block_indexes.len());
            panic!("Events haven't received");
        }
    }
}

fn subscribe_to_events(btf: &mut BlockTestFrameWork, events: &EventList) {
    let events = Arc::clone(events);
    // Add the genesis
    events.lock().unwrap().push((btf.genesis().get_id(), BlockHeight::from(0)));
    assert!(!events.lock().unwrap().is_empty());
    // Event handler
    let subscribe_func = Arc::new(
        move |consensus_event: ConsensusEvent| match consensus_event {
            ConsensusEvent::NewTip(block_id, block_height) => {
                events.lock().unwrap().push((block_id, block_height));
                assert!(!events.lock().unwrap().is_empty());
            }
        },
    );
    btf.consensus.subscribe_to_events(subscribe_func);
}

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

use std::sync::Arc;
use std::sync::Mutex;

use common::chain::OutputSpentState;

use crate::tests::EventList;
use chainstate::BlockError;
use chainstate::BlockSource;
use chainstate::ChainstateError;
use chainstate::ChainstateEvent;
use chainstate::ConnectTransactionError;
use chainstate_test_framework::TestFramework;
use common::chain::Block;
use common::chain::GenBlock;
use common::chain::OutPointSourceId;
use common::chain::Transaction;
use common::primitives::BlockHeight;
use common::primitives::Id;
use common::primitives::Idable;
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

// Produce `genesis -> a` chain, then a parallel `genesis -> b -> c` that should trigger a reorg.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_simple(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();
        let genesis_id = tf.genesis().get_id();
        assert_eq!(tf.best_block_id(), genesis_id);

        let block_a =
            tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();
        tf.process_block(block_a.clone(), BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), block_a.get_id());

        // Produce the parallel chain.
        let block_b = tf
            .make_block_builder()
            .add_test_transaction_with_parent(genesis_id.into(), &mut rng)
            .with_parent(genesis_id.into())
            .build();
        assert_ne!(block_a.get_id(), block_b.get_id());
        tf.process_block(block_b.clone(), BlockSource::Local).unwrap();
        assert_ne!(tf.best_block_id(), genesis_id);
        assert_eq!(tf.best_block_id(), block_a.get_id());

        // Produce one more block that causes a reorg.
        let block_c = tf
            .make_block_builder()
            .add_test_transaction_with_parent(block_b.get_id().into(), &mut rng)
            .with_parent(block_b.get_id().into())
            .build();
        tf.process_block(block_c.clone(), BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), block_c.get_id());
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_very_long_reorgs(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();
        let events: EventList = Arc::new(Mutex::new(Vec::new()));
        subscribe_to_events(&mut tf, &events);

        check_simple_fork(&mut tf, &events, &mut rng);
        check_make_alternative_chain_longer(&mut tf, &events, &mut rng);
        check_reorg_to_first_chain(&mut tf, &events, &mut rng);
        check_spend_tx_in_failed_block(&mut tf, &events, &mut rng);
        check_spend_tx_in_other_fork(&mut tf, &mut rng);
        check_fork_that_double_spends(&mut tf, &mut rng);

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

fn check_spend_tx_in_failed_block(tf: &mut TestFramework, events: &EventList, rng: &mut impl Rng) {
    // Check spending of a transaction in a block which failed to connect
    //
    //+-- 0x07e3…6fe4 (H:8,M,B:10)
    //      +-- 0xe40f…4d5b (H:9,M,B:11)  <-------------------------------+
    //      +-- 0xe35a…7737 (H:9,M,B:12) spend tx from the previous block +
    //
    const NEW_CHAIN_START_ON: usize = 6;
    const NEW_CHAIN_END_ON: usize = 11;

    tf.create_chain(
        &(*tf.index_at(NEW_CHAIN_START_ON).block_id()).into(),
        5,
        rng,
    )
    .unwrap();
    check_last_event(tf, events);

    let block = tf.block(*tf.index_at(NEW_CHAIN_END_ON - 1).block_id());
    let spend_from = *tf.index_at(NEW_CHAIN_END_ON).block_id();
    tf.make_block_builder()
        .with_parent(block.get_id().into())
        .add_double_spend_transaction(block.get_id().into(), spend_from, rng)
        .build_and_process()
        .unwrap();
    // Cause reorg on a failed block
    assert_eq!(
        tf.create_chain(&(*tf.index_at(12).block_id()).into(), 1, rng).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::MissingOutputOrSpent
        ))
    );
}

fn check_spend_tx_in_other_fork(tf: &mut TestFramework, rng: &mut impl Rng) {
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
    tf.create_chain(
        &(*tf.index_at(NEW_CHAIN_START_ON).block_id()).into(),
        1,
        rng,
    )
    .unwrap();
    let block = tf.block(*tf.index_at(NEW_CHAIN_END_ON).block_id());
    let spend_from = *tf.index_at(3).block_id();
    let double_spend_block = tf
        .make_block_builder()
        .with_parent(block.get_id().into())
        .add_double_spend_transaction(block.get_id().into(), spend_from, rng)
        .build();
    let block_id = double_spend_block.get_id();
    tf.process_block(double_spend_block, BlockSource::Local).unwrap();
    // Cause reorg on a failed block
    assert_eq!(
        tf.create_chain(&block_id.into(), 10, rng).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::MissingOutputOrSpent
        ))
    );
}

fn check_fork_that_double_spends(tf: &mut TestFramework, rng: &mut impl Rng) {
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
    let block = tf.block(*tf.block_indexes.last().unwrap().block_id());
    let spend_from = *tf.index_at(6).block_id();
    assert_eq!(
        tf.make_block_builder()
            .with_parent(block.get_id().into())
            .add_double_spend_transaction(block.get_id().into(), spend_from, rng)
            .build_and_process()
            .unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::MissingOutputOrSpent
        ))
    );
}

fn check_reorg_to_first_chain(tf: &mut TestFramework, events: &EventList, rng: &mut impl Rng) {
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
    let block_id: Id<GenBlock> = (*tf.index_at(2).block_id()).into();
    tf.create_chain(&block_id, 2, rng).unwrap();
    check_last_event(tf, events);

    // b3
    check_block_status(
        tf,
        tf.index_at(3).block_id(),
        &(*tf.index_at(1).block_id()).into(),
        None,
        2,
        TestSpentStatus::NotInMainchain,
    );
    assert!(!is_block_in_main_chain(tf, tf.index_at(3).block_id()));
    // b4
    check_block_status(
        tf,
        tf.index_at(4).block_id(),
        &(*tf.index_at(3).block_id()).into(),
        None,
        3,
        TestSpentStatus::NotInMainchain,
    );
    assert!(!is_block_in_main_chain(tf, tf.index_at(4).block_id()));
    // b5
    check_block_status(
        tf,
        tf.index_at(5).block_id(),
        &(*tf.index_at(2).block_id()).into(),
        Some(tf.index_at(6).block_id()),
        3,
        TestSpentStatus::Spent,
    );
    assert!(is_block_in_main_chain(tf, tf.index_at(5).block_id()));
    // b6
    check_block_status(
        tf,
        tf.index_at(6).block_id(),
        &(*tf.index_at(5).block_id()).into(),
        None,
        4,
        TestSpentStatus::Unspent,
    );
    assert!(is_block_in_main_chain(tf, tf.index_at(6).block_id()));
}

fn check_make_alternative_chain_longer(
    tf: &mut TestFramework,
    events: &EventList,
    rng: &mut impl Rng,
) {
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
    let block = tf.block(*tf.block_indexes.last().unwrap().block_id());
    tf.make_block_builder()
        .with_parent(block.get_id().into())
        .add_test_transaction_from_block(&block, rng)
        .build_and_process()
        .unwrap();
    check_last_event(tf, events);
    // b3
    check_block_status(
        tf,
        tf.index_at(3).block_id(),
        &(*tf.index_at(1).block_id()).into(),
        Some(tf.index_at(4).block_id()),
        2,
        TestSpentStatus::Spent,
    );
    assert!(is_block_in_main_chain(tf, tf.index_at(3).block_id()));
    // b4
    check_block_status(
        tf,
        tf.index_at(4).block_id(),
        &(*tf.index_at(3).block_id()).into(),
        None,
        3,
        TestSpentStatus::Unspent,
    );
    assert!(is_block_in_main_chain(tf, tf.index_at(4).block_id()));
}

fn check_simple_fork(tf: &mut TestFramework, events: &EventList, rng: &mut impl Rng) {
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
    assert!(tf.create_chain(&tf.genesis().get_id().into(), 2, rng).is_ok());
    check_last_event(tf, events);
    assert!(tf.create_chain(&(*tf.index_at(1).block_id()).into(), 1, rng).is_ok());
    check_last_event(tf, events);

    check_block_status(
        tf,
        tf.index_at(1).block_id(),
        &tf.genesis().get_id().into(),
        Some(tf.index_at(2).block_id()),
        1,
        TestSpentStatus::Spent,
    );
    assert!(is_block_in_main_chain(tf, tf.index_at(1).block_id()));
    // b2
    check_block_status(
        tf,
        tf.index_at(2).block_id(),
        &(*tf.index_at(1).block_id()).into(),
        None,
        2,
        TestSpentStatus::Unspent,
    );
    assert!(is_block_in_main_chain(tf, tf.index_at(2).block_id()));
    // b3
    check_block_status(
        tf,
        tf.index_at(3).block_id(),
        &(*tf.index_at(1).block_id()).into(),
        None,
        2,
        TestSpentStatus::NotInMainchain,
    );
    assert!(!is_block_in_main_chain(tf, tf.index_at(3).block_id()));
}

fn check_last_event(tf: &mut TestFramework, events: &EventList) {
    // We don't send any events for blocks in the middle of the chain during reorgs.
    tf.chainstate.wait_for_all_events();
    let events = events.lock().unwrap();
    assert!(!events.is_empty());
    match events.last() {
        Some((block_id, block_height)) => {
            let block_index = tf.block_indexes.last().unwrap();
            if is_block_in_main_chain(tf, block_index.block_id()) {
                // If block not in main chain then it means we didn't receive a new tip event. Nothing to check!
                assert!(block_id == block_index.block_id());
                assert!(block_height == &block_index.block_height());
            }
        }
        None => {
            panic!("Events haven't received");
        }
    }
}

fn subscribe_to_events(tf: &mut TestFramework, events: &EventList) {
    let events = Arc::clone(events);
    // Event handler
    let subscribe_func = Arc::new(
        move |chainstate_event: ChainstateEvent| match chainstate_event {
            ChainstateEvent::NewTip(block_id, block_height) => {
                events.lock().unwrap().push((block_id, block_height));
                assert!(!events.lock().unwrap().is_empty());
            }
        },
    );
    tf.chainstate.subscribe_to_events(subscribe_func);
}

fn check_block_status(
    tf: &TestFramework,
    block_id: &Id<Block>,
    prev_block_id: &Id<GenBlock>,
    next_block_id: Option<&Id<Block>>,
    height: u64,
    spend_status: TestSpentStatus,
) {
    if spend_status != TestSpentStatus::NotInMainchain {
        match tf.block_indexes.iter().find(|x| x.block_id() == block_id) {
            Some(block_index) => {
                let block = tf.chainstate.get_block(*block_index.block_id()).unwrap().unwrap();
                for tx in block.transactions() {
                    check_spend_status(tf, tx.transaction(), &spend_status);
                }
            }
            None => {
                panic!("block not found")
            }
        }
    }

    let block_index = tf.chainstate.get_block_index(block_id).unwrap().unwrap();
    assert_eq!(*block_index.prev_block_id(), *prev_block_id);
    assert_eq!(block_index.block_height(), BlockHeight::new(height));
    check_block_at_height(tf, block_index.block_height().next_height(), next_block_id);
}

fn check_block_at_height(
    tf: &TestFramework,
    block_height: BlockHeight,
    expected_block_id: Option<&Id<Block>>,
) {
    if expected_block_id.is_some() {
        let real_next_block_id = tf.chainstate.get_block_id_from_height(&block_height).unwrap();
        let expected_block_id: Option<Id<GenBlock>> = expected_block_id.map(|id| (*id).into());
        assert_eq!(real_next_block_id, expected_block_id);
    }
}

fn is_block_in_main_chain(tf: &TestFramework, block_id: &Id<Block>) -> bool {
    let block_index = tf.block_index(&(*block_id).into());
    let height = block_index.block_height();
    tf.chainstate
        .get_block_id_from_height(&height)
        .unwrap()
        .map_or(false, |id| id == block_index.block_id())
}

#[derive(Debug, Eq, PartialEq)]
pub enum TestSpentStatus {
    Spent,
    Unspent,
    NotInMainchain,
}

fn spent_status(
    tf: &TestFramework,
    tx_id: &Id<Transaction>,
    output_index: u32,
) -> Option<OutputSpentState> {
    let tx_index =
        tf.chainstate.get_mainchain_tx_index(&OutPointSourceId::from(*tx_id)).unwrap()?;
    tx_index.get_spent_state(output_index).ok()
}

fn check_spend_status(tf: &TestFramework, tx: &Transaction, spend_status: &TestSpentStatus) {
    for (output_index, _) in tx.outputs().iter().enumerate() {
        let status = spent_status(tf, &tx.get_id(), output_index as u32);
        if spend_status == &TestSpentStatus::Spent {
            assert_ne!(status, Some(OutputSpentState::Unspent));
        } else {
            assert_eq!(status, Some(OutputSpentState::Unspent));
        }
    }
}
